package com.apf.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * APFVpnService — служба APF на Android.
 *
 * ДВА РЕЖИМА, и они принципиально разные по риску:
 *
 *  РЕЖИМ «ПРОКСИ» (ACTION_CONNECT_PROXY) — рабочий сейчас.
 *      TUN не создаётся, маршруты ОС не трогаются. Ядро поднимает sing-box с локальным
 *      SOCKS5-слушателем. Системный трафик идёт мимо APF, поэтому потерять интернет на
 *      телефоне физически невозможно. Именно в этом режиме проверяются подбор узла,
 *      переключение, парсер, источники и сборка конфигурации (этап Э-3, GATE-3).
 *
 *  РЕЖИМ «VPN» (ACTION_CONNECT_VPN) — реализован на этапе Э-4 (Ш-1…Ш-4), НЕ ПРОВЕРЕН
 *  на устройстве (Ш-6 — приёмка на телефоне — ещё не пройдена).
 *      Прежний код создавал TUN и никуда не передавал его fd (дефект D-A3), из-за чего
 *      весь трафик уходил в туннель, из которого никто не читает — гарантированная
 *      потеря связи. Дополнительно: sing-box запускался дочерним процессом, а его сокет
 *      невозможно было protect() — трафик самого sing-box заворачивался бы обратно в
 *      туннель (дефект D-A4). Оба дефекта сняты переносом sing-box внутрь процесса
 *      (internal/singbox.InProcessRunner) и методом androidbridge.StartTun(fd, mtu):
 *      startVpn() передаёт detachFd() от Builder.establish() в Go-слой, ProtectCallback
 *      привязан к унаследованному VpnService.protect(fd).
 */
class APFVpnService : VpnService(), CoroutineScope {

    companion object {
        const val TAG = "APFVpnService"

        const val ACTION_CONNECT_PROXY = "com.apf.ACTION_CONNECT_PROXY"
        const val ACTION_CONNECT_VPN = "com.apf.ACTION_CONNECT_VPN"
        // Находка Ш-6: подключение к КОНКРЕТНОМУ узлу в режиме VPN, минуя случайный подбор
        // (см. ApfCore.startTunToNode). EXTRA_NODE_LINK — обязателен для этого действия.
        const val ACTION_CONNECT_VPN_TO_NODE = "com.apf.ACTION_CONNECT_VPN_TO_NODE"
        // U-18 (ТЗ v1.4): симметричное действие для режима «Прокси». Раньше подключиться к
        // КОНКРЕТНОЙ вставленной ссылке можно было только в режиме VPN — и именно поэтому
        // кнопка «Подключить» вела себя по-разному в двух режимах при одном и том же
        // непустом поле (E2 #16). Теперь у «Добавить и подключиться» один смысл в обоих.
        const val ACTION_CONNECT_PROXY_TO_NODE = "com.apf.ACTION_CONNECT_PROXY_TO_NODE"
        const val EXTRA_NODE_LINK = "node_link"
        // Живая находка 2026-09-28: ссылка — от партнёра «Вход-Выход» (IsChainPartner).
        // Добавочный флаг к ACTION_CONNECT_{VPN,PROXY}_TO_NODE, а не отдельные действия:
        // путь подключения (TUN или прокси, ожидание подтверждения, статус) тот же самый.
        const val EXTRA_CHAIN_PARTNER = "chain_partner"
        // ТЗ v1.3 F6/КТ-14: подключение к узлу из «Моих серверов» по ID — через службу (экран
        // и уведомление обновляет она), не прямым вызовом ядра из активити. Пин не меняется.
        const val ACTION_CONNECT_VPN_TO_NODE_ID = "com.apf.ACTION_CONNECT_VPN_TO_NODE_ID"
        const val ACTION_CONNECT_PROXY_TO_NODE_ID = "com.apf.ACTION_CONNECT_PROXY_TO_NODE_ID"
        const val EXTRA_NODE_ID = "node_id"
        const val ACTION_DISCONNECT = "com.apf.ACTION_DISCONNECT"

        /**
         * C-9 (ТЗ v1.4): честная причина, по которой служба поднялась НЕ в том режиме, о
         * котором просил пользователь. Сейчас единственный источник — BootReceiver: режим
         * VPN выбран, но системного согласия на туннель после перезагрузки нет, а показать
         * системный диалог из приёмника нельзя. Молча подменить режим — та самая тихая
         * деградация защиты, поэтому причина доезжает до уведомления.
         */
        const val EXTRA_START_NOTICE = "start_notice"

        // Роль «Выход» (Э-Выход-2) — независимый от Connect/StartTun жизненный цикл,
        // см. комментарий у startServerRole ниже.
        const val ACTION_START_SERVER_ROLE = "com.apf.ACTION_START_SERVER_ROLE"
        const val ACTION_STOP_SERVER_ROLE = "com.apf.ACTION_STOP_SERVER_ROLE"
        const val EXTRA_SERVER_PORT = "server_port"
        const val EXTRA_SERVER_REALITY_DEST = "server_reality_dest"
        const val EXTRA_SERVER_IDENTITY = "server_identity_json"
        // Фаза E (docs/PLAN_APF_RELAY_v1.0.md): лимит одновременных «Входов» и опциональный
        // relay-fallback — те же параметры, что StartServerRole на Windows (Engine.cfg.
        // MaxConnectedClients/RelayServerAddr), здесь передаются через Intent, а не
        // персистентный конфиг (на Android роль «Выход» ещё не имеет своего хранимого
        // конфига — тот же статус, что у identity, см. serverRoleIdentityJson комментарий
        // в MainActivity.kt). 0 ⇒ платформенный дефолт (2, ТЗ §10.1), пусто ⇒ без relay.
        const val EXTRA_SERVER_MAX_CLIENTS = "server_max_clients"
        const val EXTRA_SERVER_RELAY_ADDR = "server_relay_addr"
        // Отпечаток TLS-сертификата relay (TZ_RELAY_HARDENING_2026-08-29.md кластер B) —
        // обязателен вместе с EXTRA_SERVER_RELAY_ADDR, иначе ExitClient откажет fail-closed.
        const val EXTRA_SERVER_RELAY_FINGERPRINT = "server_relay_fingerprint"

        const val CHANNEL_ID = "apf_vpn"
        const val NOTIF_ID = 1001

        const val BROADCAST_STATE = "com.apf.STATE_CHANGED"

        /**
         * ПОДТВЕРЖДЁННОЕ подключение, а не просто поднятый туннель (дефект D9).
         *
         * Раньше здесь стояло `currentState == State.CONNECTED`, а состояние CONNECTED
         * объявляется и при исходе UNVERIFIED — то есть «канал не подтверждён» уезжало в UI
         * как честное «connected=true». Само решение НЕ рвать неподтверждённый туннель
         * остаётся в силе (см. ConnectOutcome.UNVERIFIED — оно закрывает отдельный дефект);
         * меняется только то, что об этом канале СООБЩАЕТСЯ. Тому, кому нужен факт «сеанс
         * живёт, есть что отключать», предназначен EXTRA_SESSION_ACTIVE / isSessionActive().
         */
        const val EXTRA_CONNECTED = "connected"

        /** Сеанс поднят (есть что отключать), независимо от подтверждения канала. */
        const val EXTRA_SESSION_ACTIVE = "session_active"

        /** idle | checking | verified | failed — общий контракт трёх UI (см. ApfCore.kt). */
        const val EXTRA_VERIFY_STATE = "verify_state"

        /** Задержка по сквозной HTTP-проверке, мс; 0 — такого замера не было (D12).
         *  C-20: «через туннель» она называется только при source=tun, см. buildNotification. */
        const val EXTRA_VERIFIED_LATENCY = "verified_latency_ms"

        const val EXTRA_NODE_NAME = "node_name"
        const val EXTRA_LATENCY = "latency_ms"
        const val EXTRA_STATE = "state"
        const val EXTRA_MESSAGE = "message"

        const val BROADCAST_SERVER_ROLE_STATE = "com.apf.SERVER_ROLE_STATE_CHANGED"
        const val EXTRA_SERVER_RUNNING = "server_running"
        const val EXTRA_SERVER_MESSAGE = "server_message"

        /** Сколько ждём готовности ядра, мс. */
        /**
         * Срок, после которого пользователю сообщается, что подбор затянулся (дефект D-A32).
         * Это НЕ отказ: ядро в этот момент продолжает работать.
         */
        private const val CONNECT_SLOW_MS = 20_000L

        /**
         * Настоящий предел ожидания. Измерено на устройстве: от нажатия до
         * «sing-box started» проходило 28 с (подбор узла + проверка + запуск), а
         * до рабочего узла — 2 мин 12 с, потому что движок обязан выждать
         * MinUptimeSec, прежде чем сменить неудачный узел.
         *
         * 20 секунд, стоявшие здесь раньше, были короче штатного пути подключения —
         * то есть отказ объявлялся практически всегда.
         */
        private const val CONNECT_TIMEOUT_MS = 180_000L
        private const val POLL_INTERVAL_MS = 500L

        /** MTU TUN-интерфейса — передаётся и в Builder.setMtu(), и в androidbridge.startTun,
         * чтобы буферы netstack sing-box совпадали с тем, что реально настроено на
         * интерфейсе (см. TunOptions.MTU, internal/singbox/config_builder.go). */
        private const val TUN_MTU = 1500
    }

    // VERIFYING — сокет sing-box поднят (ApfCore.isConnected()=true), но узел ещё не
    // подтвердил реальный сквозной трафик (ApfCore.isVerified()=false). Отдельное состояние,
    // а не сразу CONNECTED — см. awaitVerifiedConnection() и apf-russia-nodes-no-internet в
    // памяти проекта: пользователь видел "подключено" на мёртвом узле и переподключался
    // вручную раньше, чем движок находил рабочую замену.
    enum class State { IDLE, CONNECTING, VERIFYING, CONNECTED, DISCONNECTING, ERROR }

    enum class Mode { NONE, PROXY, VPN }

    // @Volatile — консилиум 2026-08-10 (HIGH): каждый Intent обрабатывается в отдельной
    // корутине на Dispatchers.IO (реальный пул потоков, не единственный поток). Без этого
    // гонка реальна: коннект по pinned-ссылке пишет currentMode=VPN в конце startVpn(),
    // почти одновременный disconnect может прочитать currentMode раньше, чем запись видна
    // другому потоку (JMM), stopEverything() берёт неверную ветку — VPN TUN/InProcessRunner
    // остаются работать, хотя UI уже показывает IDLE. @Volatile достаточно: полям присваивают
    // целиком (не read-modify-write), нужна только видимость записи между потоками.
    @Volatile private var currentState = State.IDLE
    @Volatile private var currentMode = Mode.NONE
    private var lastMessage = ""

    /**
     * Последнее известное состояние проверки канала (idle|checking|verified|failed).
     *
     * @Volatile по той же причине, что и currentState: пишется из корутин Dispatchers.IO
     * (setState, монитор состояния), читается из уведомления и Binder-геттеров, которые
     * зовёт главный поток активности.
     *
     * Дефекты D3/D5/D6: раньше признака подтверждения не было ни в уведомлении, ни в
     * бродкасте, а монитор следил только за `connected` — деградация «подтверждён →
     * не подтверждён» для пользователя была НЕВИДИМА до конца сеанса.
     */
    @Volatile private var currentVerifyState = VERIFY_IDLE

    /** Задержка по сквозной HTTP-проверке (D12); 0 — такого замера не было. C-20: чем именно
     * она получена, отвечает ApfCore.activeNodeVerifiedLatencySource(). */
    @Volatile private var currentVerifiedLatency = 0

    /**
     * Служба уже переведена на передний план хотя бы раз.
     *
     * Нужен, чтобы перевыпуск уведомления (refreshNotification) не создавал «висячее»
     * уведомление на путях, где startForeground ещё не звался (ошибка инициализации ядра
     * из onCreate) — такое уведомление некому было бы снять stopForeground().
     */
    @Volatile private var foregroundStarted = false

    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
    private var statusJob: Job? = null

    /**
     * Текущая попытка подключения. Нужна, чтобы УСТАРЕВШАЯ попытка не могла тронуть чужой
     * сеанс (найдено ревью 2026-08-24).
     *
     * Корутина подключения живёт до 180 секунд (ждёт подтверждения канала) и завязана на
     * глобальное состояние движка, а не на свою попытку. `stopEverything()` отменял только
     * statusJob, общий job — лишь в onDestroy(), а служба переживает stopSelf(), пока её
     * держит связанная активность. Поэтому воспроизводился такой сценарий: подключиться,
     * отключиться на 40-й секунде, ничего не делать — и через 2.5 минуты экран сам
     * перескакивал с «Отключено» на «Ошибка». Хуже, если за это время пользователь
     * подключился снова: ветка отказа звала stopTun(), гасящий движок и закрывающий
     * дескриптор, принадлежащий уже НОВОЙ попытке.
     */
    private var connectJob: Job? = null
    private val connectJobMu = Any()

    private var engineReady = false

    private val job = SupervisorJob()
    override val coroutineContext = Dispatchers.IO + job

    private val binder = LocalBinder()

    inner class LocalBinder : Binder() {
        fun getService() = this@APFVpnService
    }

    // ─── Жизненный цикл ───────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        initEngine()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // startForeground обязан быть вызван в первые 5 секунд на ЛЮБОМ пути, иначе система
        // убивает службу с ForegroundServiceDidNotStartInTimeAllowedException (дефект D-A20).
        // Прежняя версия звала его только в ветке ACTION_CONNECT_PROXY, поэтому и отказ
        // VPN-режима, и восстановление службы после гибели процесса заканчивались падением.
        //
        // ЭТОТ вызов трогать нельзя: он обязан оставаться первым действием onStartCommand и
        // выполняться синхронно. Исправление D3 (уведомление, отражающее реальность)
        // добавляет ПЕРЕВЫПУСК уведомления позже — см. refreshNotification(), — а не
        // переносит и не откладывает этот вызов.
        startForeground(NOTIF_ID, buildNotification())
        foregroundStarted = true
        ApfFileLogger.log("I", TAG, "onStartCommand: action=${intent?.action}")

        // C-9: причина вынужденной смены режима (BootReceiver) — в уведомление, а не в лог.
        // Ставится ДО ветвления по действию: startProxy сразу перепишет lastMessage своим
        // «подбираю сервер», поэтому причина показывается отдельным уведомлением.
        intent?.getStringExtra(EXTRA_START_NOTICE)?.takeIf { it.isNotEmpty() }?.let { notice ->
            Log.w(TAG, "старт с оговоркой: $notice")
            ApfFileLogger.log("W", TAG, "старт с оговоркой: $notice")
            showStartNoticeNotification(notice)
        }

        when (intent?.action) {
            ACTION_CONNECT_PROXY -> startAttempt { startProxy() }
            ACTION_CONNECT_VPN -> startAttempt { startVpn(null) }
            ACTION_CONNECT_VPN_TO_NODE -> {
                val link = intent.getStringExtra(EXTRA_NODE_LINK).orEmpty()
                if (link.isEmpty()) {
                    Log.w(TAG, "ACTION_CONNECT_VPN_TO_NODE без EXTRA_NODE_LINK — завершаю службу")
                    launch { stopEverything() }
                } else {
                    val partner = intent.getBooleanExtra(EXTRA_CHAIN_PARTNER, false)
                    startAttempt { startVpn(link, chainPartner = partner) }
                }
            }
            ACTION_CONNECT_VPN_TO_NODE_ID -> {
                val id = intent.getStringExtra(EXTRA_NODE_ID).orEmpty()
                if (id.isEmpty()) {
                    Log.w(TAG, "ACTION_CONNECT_VPN_TO_NODE_ID без EXTRA_NODE_ID — завершаю службу")
                    launch { stopEverything() }
                } else {
                    startAttempt { startVpn(null, id) }
                }
            }
            ACTION_CONNECT_PROXY_TO_NODE -> {
                val link = intent.getStringExtra(EXTRA_NODE_LINK).orEmpty()
                if (link.isEmpty()) {
                    Log.w(TAG, "ACTION_CONNECT_PROXY_TO_NODE без EXTRA_NODE_LINK — завершаю службу")
                    launch { stopEverything() }
                } else {
                    val partner = intent.getBooleanExtra(EXTRA_CHAIN_PARTNER, false)
                    startAttempt { startProxy(nodeLink = link, chainPartner = partner) }
                }
            }
            ACTION_CONNECT_PROXY_TO_NODE_ID -> {
                val id = intent.getStringExtra(EXTRA_NODE_ID).orEmpty()
                if (id.isEmpty()) {
                    Log.w(TAG, "ACTION_CONNECT_PROXY_TO_NODE_ID без EXTRA_NODE_ID — завершаю службу")
                    launch { stopEverything() }
                } else {
                    startAttempt { startProxy(id) }
                }
            }
            ACTION_DISCONNECT -> launch {
                // Отменяем незавершённую попытку подключения ДО уборки: иначе она доживёт до
                // своего таймаута и уже после отключения объявит «не удалось подключиться»,
                // а в худшем случае снесёт туннель, поднятый следующей попыткой.
                cancelConnectAttempt()
                stopEverything()
            }
            ACTION_START_SERVER_ROLE -> {
                val port = intent.getIntExtra(EXTRA_SERVER_PORT, 0)
                val realityDest = intent.getStringExtra(EXTRA_SERVER_REALITY_DEST).orEmpty()
                val identity = intent.getStringExtra(EXTRA_SERVER_IDENTITY).orEmpty()
                val maxClients = intent.getIntExtra(EXTRA_SERVER_MAX_CLIENTS, 0)
                val relayAddr = intent.getStringExtra(EXTRA_SERVER_RELAY_ADDR).orEmpty()
                val relayFingerprint = intent.getStringExtra(EXTRA_SERVER_RELAY_FINGERPRINT).orEmpty()
                launch { startServerRole(port, realityDest, identity, maxClients, relayAddr, relayFingerprint) }
            }
            ACTION_STOP_SERVER_ROLE -> launch { stopServerRole() }
            null -> {
                // Служба воскрешена системой без исходного намерения. Ядро при этом
                // инициализировано, но сеанса нет. Тихо остаться в фоне — значит копить
                // ровно то остаточное состояние, ради отсутствия которого стенд и создан.
                // Полная уборка ОБОИХ независимых путей (клиент + роль «Выход») — здесь,
                // в отличие от ACTION_DISCONNECT/onRevoke, нет пользовательского намерения
                // сохранить роль «Выход» работающей, поэтому не действует симметричная
                // защита stopEverything() (см. её комментарий про isServerRoleRunning()).
                Log.w(TAG, "перезапуск без намерения — завершаю службу")
                launch { stopEverything(); stopServerRoleQuietly(); forceStopService() }
            }
            else -> {
                Log.w(TAG, "неизвестное действие: ${intent.action} — завершаю службу")
                launch { stopEverything(); stopServerRoleQuietly(); forceStopService() }
            }
        }

        // НЕ START_STICKY: воскрешение с пустым намерением создаёт «зомби» — живую службу
        // без сеанса, которую пользователь не видит и не может остановить. Подключением
        // на стенде управляет только человек.
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onRevoke() {
        Log.w(TAG, "VPN-разрешение отозвано пользователем")
        launch { stopEverything() }
        super.onRevoke()
    }

    override fun onDestroy() {
        ApfFileLogger.log("I", TAG, "onDestroy")
        // Прежняя версия звала suspend-функцию из onDestroy напрямую (дефект D-A2: не
        // компилировалось) и вдобавок делала job.cancel() ДО уборки, из-за чего уборка
        // не выполнилась бы и после исправления. Порядок обратный: сначала убрать, потом
        // отменить область корутин.
        statusJob?.cancel()
        runBlocking { stopEverything() }
        // Процесс уничтожается целиком независимо от того, что решил forceStopServiceIfIdle()
        // внутри stopEverything() — роль «Выход» обязана остановиться здесь безусловно,
        // иначе её in-process sing-box-инстанс (androidServerRunner) переживает Kotlin-службу
        // как осиротевший объект до самой смерти процесса.
        stopServerRoleQuietly()
        job.cancel()
        try {
            ApfCore.shutdown()
        } catch (e: Throwable) {
            Log.e(TAG, "shutdown: $e")
            ApfFileLogger.log("E", TAG, "shutdown: $e")
        }
        super.onDestroy()
    }

    // ─── Инициализация ядра ───────────────────────────────────────────────────

    private fun initEngine() {
        try {
            // nativeLibraryDir обязателен: оттуда запускается libsingbox.so. Без него ядро
            // ищет бинарник рядом с исполняемым файлом, то есть в /system/bin/bin —
            // каталог чужой, и инициализация падала на создании директорий (дефект D-A11).
            val err = ApfCore.init(filesDir.absolutePath, applicationInfo.nativeLibraryDir)
            if (err.isNotEmpty()) {
                Log.e(TAG, "init: $err")
                ApfFileLogger.log("E", TAG, "init: $err")
                setState(State.ERROR, "инициализация ядра: $err")
                return
            }
            engineReady = true

            ApfCore.onLog { message ->
                Log.d(TAG, "[APF] $message")
                ApfFileLogger.log("D", TAG, message)
            }
            // Живой ANR 2026-08-28 (реальное устройство, Ulefone): onStateChanged зовётся
            // СИНХРОННО из Go (см. Engine.setDisconnected/OnStateChange) — вызывающий
            // goroutine в этот момент находится ВНУТРИ Go-кода (например, Stop()). Если
            // прямо здесь же (тем же вызовом) снова дёрнуть Go через ApfCore.* (что и
            // делает broadcastState() → safeNodeName()/safeLatency()), это реентерабельный
            // вызов Go→Kotlin→Go через один и тот же gomobile/gobind JNI-мост — тот
            // намертво виснет (permanent futex wait, подтверждено ANR-трейсом:
            // Subject: executing service .../.APFVpnService, стек — Engine.Stop →
            // setDisconnected → OnStateChange → broadcastState → activeNodeName, снова
            // Go). launch{} (Dispatchers.IO) переносит вызов на отдельный поток вне
            // исходного Go-стека — тот же приём, что уже используется для остальной
            // асинхронной работы в этом файле.
            //
            // D3/D5: вместе с бродкастом обновляем снимок проверенности и перевыпускаем
            // уведомление. Смена узла движком (emergencySwitch) приходит именно сюда, и
            // раньше после неё в шторке продолжали висеть имя и задержка ПРЕЖНЕГО узла.
            ApfCore.onStateChanged {
                launch {
                    refreshVerifyState()
                    refreshNotification()
                    broadcastState()
                }
            }
            ApfCore.onLeak { type, details ->
                Log.w(TAG, "УТЕЧКА [$type]: $details")
                ApfFileLogger.log("W", TAG, "УТЕЧКА [$type]: $details")
                showLeakNotification(type, details)
            }

            publishSystemKillSwitchState()
            Log.i(TAG, "ядро APF инициализировано, версия ${ApfCore.version()}")
        } catch (e: Throwable) {
            Log.e(TAG, "initEngine: $e")
            setState(State.ERROR, "инициализация ядра: $e")
        }
    }

    /**
     * Сообщает ядру фактическое состояние системной защиты.
     *
     * Ключи `always_on_vpn_app` и `always_on_vpn_lockdown` — скрытые, обычному приложению
     * их чтение может быть недоступно. Если прочитать не удалось, сообщаем false:
     * при fail-closed честное «не знаю, значит не защищено» безопаснее догадки.
     * Достоверное значение снимает стендовый инструмент с ПК через adb.
     */
    private fun publishSystemKillSwitchState() {
        // C-19 (ТЗ v1.4): исходов ТРИ, а не два. `getString` для скрытого ключа обычному
        // приложению возвращает null БЕЗ исключения — то есть «не прочитал» было
        // неотличимо от «прочитал и там пусто». Ядру по-прежнему сообщается булево
        // fail-closed значение (движок обязан считать защиту отсутствующей, пока она не
        // доказана), а вот УВЕДОМЛЕНИЮ пользователя нужен третий исход: утверждать
        // «защита неполная» там, где APF просто не может прочитать настройку, нельзя.
        val read = try {
            Pair(
                Settings.Secure.getString(contentResolver, "always_on_vpn_app"),
                Settings.Secure.getInt(contentResolver, "always_on_vpn_lockdown", 0)
            )
        } catch (e: Throwable) {
            Log.w(TAG, "состояние always-on VPN недоступно: $e")
            null
        }
        val app = read?.first
        val active = read != null && app != null && app.isNotEmpty() && read.second == 1
        systemKsReadable = read != null && app != null
        ApfCore.setSystemKillSwitch(active)
        systemKsActive = active
        Log.i(
            TAG,
            "системная защита (always-on VPN + lockdown): active=$active, " +
                "ключ прочитан=$systemKsReadable"
        )
        refreshNotification()
    }

    /** C-8/C-19: ключ Settings.Secure удалось прочитать (иначе утверждать нечего). */
    @Volatile private var systemKsReadable = false

    /** C-8/C-19: системная защита фактически включена (только при systemKsReadable=true). */
    @Volatile private var systemKsActive = false

    /**
     * C-8 (ТЗ v1.4, UI_CONTRACT §5.5): нужно ли предупредить о недостающей системной
     * настройке В УВЕДОМЛЕНИИ.
     *
     * K1 добавил подсказку и кнопку перехода НА ЭКРАНЕ (живой прогон A2 — работает), но
     * шторку пользователь открывает чаще, чем само приложение, а уведомление об этом
     * молчало. Показывается по тому же условию, что и строка на экране: защита точно
     * выключена, либо прочитать нельзя и чек-лист ещё не подтверждён.
     */
    private fun needsSystemKsWarning(): Boolean {
        if (systemKsReadable) return !systemKsActive
        val acked = getSharedPreferences(MainActivity.UI_PREFS, Context.MODE_PRIVATE)
            .getBoolean(MainActivity.KEY_KS_CHECKLIST_ACK, false)
        return !acked
    }

    // ─── Режим «прокси» ───────────────────────────────────────────────────────

    /** @param nodeId null → ScanAndConnect (случайный подбор); ID → ConnectOnce к этому узлу
     *  (ТЗ v1.3 F6/КТ-14, «Мои серверы»), закрепление не меняется.
     *  @param nodeLink U-18: подключение к КОНКРЕТНОЙ вставленной ссылке в режиме «Прокси»
     *  (ConnectNode). Взаимоисключающ с nodeId; когда оба пусты — обычный подбор.
     *  @param chainPartner nodeLink — ссылка партнёра «Вход-Выход» (ConnectChainPartner:
     *  узел помечается IsChainPartner и не подменяется случайным публичным). */
    private suspend fun startProxy(
        nodeId: String? = null,
        nodeLink: String? = null,
        chainPartner: Boolean = false,
    ) = withContext(Dispatchers.IO) {
        if (!engineReady) {
            setState(State.ERROR, "ядро не инициализировано")
            return@withContext
        }
        val toSpecificNode = nodeId != null || nodeLink != null
        setState(
            State.CONNECTING,
            if (toSpecificNode) "подключаюсь к выбранному серверу" else "подбираю сервер"
        )
        currentMode = Mode.PROXY

        val err = when {
            nodeId != null -> ApfCore.connectOnce(nodeId)
            nodeLink != null && chainPartner -> ApfCore.connectChainPartner(nodeLink)
            nodeLink != null -> ApfCore.connectNode(nodeLink)
            else -> ApfCore.connect()
        }
        if (err.isNotEmpty()) {
            setState(State.ERROR, "подключение: $err")
            return@withContext
        }

        // Дефект D-A32. Раньше здесь стоял единственный срок в 20 с, после которого
        // служба объявляла ERROR и ПРЕКРАЩАЛА НАБЛЮДЕНИЕ, не прекращая саму работу.
        // На устройстве это выглядело так: в 17:00:28 экран показал «Ошибка: таймаут
        // подключения (20 с)», в 17:00:36 движок поднял туннель, в 17:02:48 переключился
        // на рабочий узел — и всё это время экран показывал «Ошибка» и кнопку «ПОВТОРИТЬ»,
        // пока через туннель шёл трафик (внешний адрес телефона отличался от прямого).
        //
        // Две разные ошибки в одном месте:
        //   1. срок был короче штатного пути подключения — отказ объявлялся почти всегда;
        //   2. объявленный отказ был неправдой: работа продолжалась, а наблюдение — нет.
        //
        // Теперь затянувшийся подбор — это состояние CONNECTING с честным пояснением,
        // а отказ наступает по настоящему пределу и СОПРОВОЖДАЕТСЯ остановкой ядра:
        // раз сказали «не удалось», ничего работать не должно (решение D-2, fail-closed).
        val outcome = awaitVerifiedConnection()
        if (outcome == ConnectOutcome.FAILED) {
            val err = ApfCore.disconnect()
            if (err.isNotEmpty()) Log.w(TAG, "остановка после неудачного подключения: $err")
            setState(State.ERROR, "не удалось подключиться за ${CONNECT_TIMEOUT_MS / 1000} с")
            return@withContext
        }

        // Текст сообщения — ПОЯСНЕНИЕ («куда подключаться приложениям»), а не источник
        // статуса: статус читается из verify_state (дефект D4 — экран определял «канал не
        // подтверждён» разбором подстроки ИМЕННО этой строки, и любая её переформулировка
        // молча ломала цвет и текст на главном экране). Само различие VERIFIED/UNVERIFIED
        // никуда не делось — оно доезжает до UI полем verify_state в broadcastState().
        setState(State.CONNECTED, "SOCKS5 на 127.0.0.1:${ApfCore.socksPort()}")
        if (outcome == ConnectOutcome.UNVERIFIED) {
            ApfFileLogger.log("W", TAG, "прокси поднят, но канал не подтверждён (verify_state=$currentVerifyState)")
        }
        startStatusMonitor()
    }

    // ─── Режим «VPN» (Э-4) ─────────────────────────────────────────────────────

    /**
     * B-A15. Собирает Builder, передаёт fd в Go-слой (B-A13) через detachFd() — владение
     * переходит ядру, и closeTun()/vpnInterface здесь не участвуют (в отличие от режима
     * «прокси»): закрывать этот fd на стороне Kotlin после detachFd() было бы либо
     * no-op, либо преждевременным закрытием чужого владения.
     *
     * Отвергает: отсутствие согласия пользователя на VPN (VpnService.prepare() вернул
     * Intent — сюда попасть не должны: активити обязана была получить его заранее),
     * establish() вернул null.
     * Fail-safe: любая ошибка на любом шаге ⇒ откат — fd закрывается (если ещё наш),
     * состояние ERROR, currentMode возвращается в NONE.
     *
     * @param link null → обычный путь (ACTION_CONNECT_VPN, случайный подбор из пула,
     *             androidbridge.startTun). Непустая строка → ACTION_CONNECT_VPN_TO_NODE
     *             (находка Ш-6, androidbridge.startTunToNode) — подключение к КОНКРЕТНОЙ
     *             ссылке, минуя случайную выборку 50 узлов из всего пула.
     */
    private suspend fun startVpn(
        link: String?,
        nodeId: String? = null,
        chainPartner: Boolean = false,
    ) = withContext(Dispatchers.IO) {
        if (!engineReady) {
            setState(State.ERROR, "ядро не инициализировано")
            return@withContext
        }
        setState(State.CONNECTING, "поднимаю TUN")
        currentMode = Mode.VPN

        val pfd = buildVpnInterface()
        if (pfd == null) {
            setState(State.ERROR, "не удалось создать TUN-интерфейс (VpnService.prepare() не пройден?)")
            currentMode = Mode.NONE
            return@withContext
        }

        // ProtectCallback (B-A02): унаследованный VpnService.protect(fd) выводит сокет
        // sing-box из-под собственного туннеля. Установить ДО startTun — sing-box
        // начинает открывать сокеты сразу после поднятия.
        ApfCore.setProtectCallback { fd -> protect(fd) }

        // Задача #11, вариант 2 (2026-08-17): Go-движок запрашивает АБСОЛЮТНО НОВЫЙ
        // TUN-интерфейс на каждом автопереключении узла (emergencySwitch) вместо
        // переиспользования этого же fd — устраняет саму возможность состояния,
        // пережившего Close() старого sing-box-инстанса (см. singbox.TunReloader,
        // androidbridge.TunFdCallback). Тоже ДО startTun: колбэк должен быть готов раньше
        // первого возможного вызова из движка.
        ApfCore.setTunFdCallback { requestTunFd() }

        // detachFd() необратимо передаёт владение сырым fd дальше — с этого момента
        // vpnInterface никогда не заполняется реальным pfd для VPN-пути (в отличие от
        // режима «прокси», здесь нечему лежать в поле класса), поэтому closeTun()/
        // vpnInterface ниже по стеку остановки закономерно его не касаются. Владение
        // и закрытие на любом отказе — забота Go-слоя (см. tun.go: prepareTun закрывает
        // fd на КАЖДОЙ ветке отказа с момента, когда fd>0 подтверждён).
        val fd = pfd.detachFd()
        val err = when {
            // ТЗ v1.3 F6/КТ-14: узел из пула по ID («Мои серверы»), закрепление не меняется.
            nodeId != null -> ApfCore.startTunToNodeId(fd, TUN_MTU, nodeId)
            link != null && chainPartner -> ApfCore.startTunToChainPartner(fd, TUN_MTU, link)
            link != null -> ApfCore.startTunToNode(fd, TUN_MTU, link)
            else -> ApfCore.startTun(fd, TUN_MTU)
        }
        if (err.isNotEmpty()) {
            // Консилиум 2026-08-10 (HIGH): комментарий функции обещает откат на любом
            // отказе, а до этой правки код откатывал только currentMode/State — Go-сторона
            // теперь сама закрывает fd и откатывает engine на своих ветках отказа (tun.go),
            // но симметричный stopTun() здесь — та же защита в глубину, что и в ветке
            // таймаута ниже: движок гарантированно возвращается в чистое состояние, даже
            // если что-то на Go-стороне осталось смонтированным по неучтённой причине.
            val stopErr = ApfCore.stopTun()
            if (stopErr.isNotEmpty()) Log.w(TAG, "остановка после неудачного запуска VPN: $stopErr")
            setState(State.ERROR, "запуск VPN: $err")
            currentMode = Mode.NONE
            return@withContext
        }

        // Тот же путь ожидания и та же деградация до "затянулось", что у startProxy
        // (дефект D-A32) — подбор узла в VPN-режиме идёт тем же ScanAndConnect().
        val outcome = awaitVerifiedConnection()
        if (outcome == ConnectOutcome.FAILED) {
            val stopErr = ApfCore.stopTun()
            if (stopErr.isNotEmpty()) Log.w(TAG, "остановка после неудачного запуска VPN: $stopErr")
            setState(State.ERROR, "не удалось подключиться за ${CONNECT_TIMEOUT_MS / 1000} с")
            currentMode = Mode.NONE
            return@withContext
        }

        // Тот же принцип, что и в startProxy: сообщение поясняет режим, статус несёт
        // verify_state (D4). Решение НЕ рвать неподтверждённый туннель (ConnectOutcome.
        // UNVERIFIED) сохраняется без изменений — меняется только то, что видит пользователь.
        setState(State.CONNECTED, "VPN активен")
        if (outcome == ConnectOutcome.UNVERIFIED) {
            ApfFileLogger.log("W", TAG, "TUN поднят, но канал не подтверждён (verify_state=$currentVerifyState)")
        }
        startStatusMonitor()
    }

    /**
     * B-A15. Адреса/маршруты обязаны СОВПАДАТЬ с tunAddressV4/tunAddressV6 в
     * config_builder.go — не «похоже», а буквально тот же адрес/префикс.
     *
     * Находка 2026-08-10 (живой прогон Э-Выход-1 на устройстве, пятый слой той же болезни,
     * что with_clash_api/with_utls/D-A34/D-A35/with_gvisor). Комментарий здесь и раньше
     * утверждал, что адреса совпадают — НЕ совпадали: `.addRoute("::", 0)` заворачивает
     * весь IPv6-трафик в туннель (защита от утечки IPv6, R-6.2/C-11 — see NewBuilder:
     * "по умолчанию IPv6 идёт В ТУННЕЛЬ"), но `.addAddress(...)` для IPv6 не звался вовсе.
     * Go-сторона (b.tunIPv6 = true по умолчанию) кладёт в конфиг TUN-inbound ОБА адреса,
     * включая fdfe:dcba:9876::1/126 (tunAddressV6), и gVisor-стек sing-tun пытается открыть
     * слушающий сокет на этом адресе — а системный TUN-интерфейс, у которого Android ни разу
     * не попросили этот адрес назначить, его не имеет:
     *
     *	post-start inbound/tun[tun-in]: starting tun stack: listen tcp6
     *	[fdfe:dcba:9876::1]:0: bind: cannot assign requested address
     *
     * Значит защита от утечки IPv6 на Android НЕ РАБОТАЛА НИ РАЗУ, даже до того, как
     * остальные четыре слоя блокировали VPN-режим целиком — этот адрес просто никогда не
     * доходил до реальной проверки. Исправление — не выключить v6-маршрут (это откатило бы
     * защиту от C-11), а добавить недостающий `.addAddress`, чтобы Kotlin и Go сходились.
     */
    private fun buildVpnInterface(): ParcelFileDescriptor? = try {
        Builder()
            .setSession("APF")
            .addAddress("172.19.0.1", 30)
            .addAddress("fdfe:dcba:9876::1", 126)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // Находка 2026-08-11 (живой прогон: Chrome не открывал ни одного сайта в
            // VPN-режиме, хотя внутренние проверки APF были зелёными — см.
            // FULL_RUN_RESULTS_2026-08-11.md / TZ_VPN_TUN_REAL_TRAFFIC_2026-08-11.md).
            // Раньше здесь стоял РЕАЛЬНЫЙ публичный резолвер "1.1.1.1" — Android
            // (Приватный DNS: Автоматически) пробует DNS-over-TLS на порт 853 к ЛЮБОМУ
            // адресу, объявленному через addDnsServer(). hijack-dns в config_builder.go
            // ловит только открытый (не в TLS) формат DNS по сниффингу протокола — DoT
            // на 853 уходит обычным TCP через прокси-узел, и если конкретный узел не
            // пропускает нестандартный порт (частое ограничение бесплатных узлов),
            // резолвинг виснет в долгом таймауте вместо отката на UDP:53.
            //
            // Вторая находка того же дня, ПОСЛЕ фикса выше (живой прогон с проброшенными
            // debug-логами sing-box, D-A37, Task #25): адрес САМОГО TUN-шлюза (172.19.0.1)
            // здесь не годится — это адрес, назначенный интерфейсу tun0 через addAddress
            // выше, а `ip route get 172.19.0.1` на устройстве показал `dev lo`: ядро Linux
            // трактует пакеты К СОБСТВЕННОМУ адресу интерфейса как локальные и заворачивает
            // их через loopback, они НИКОГДА не доходят до реального tun0/sing-box (который
            // слушает только то, что реально пишется в TUN-fd) — UDP:53 без слушателя на
            // loopback отвечает мгновенным отказом, что и выглядело как "DNS не резолвится".
            // 172.19.0.2 — адрес того же /30-подсети (172.19.0.1/30 → сеть 172.19.0.0/30,
            // хосты .1–.2), но НЕ назначенный ни одному интерфейсу: `ip route get 172.19.0.2`
            // подтверждённо показывает `dev tun0` — обычный маршрут по directly-connected
            // префиксу, пакет реально уходит в TUN и корректно перехватывается hijack-dns.
            // Не похож на публичный DoT-резолвер по тем же причинам, что и .1.
            .addDnsServer("172.19.0.2")
            .setMtu(TUN_MTU)
            .apply {
                // Само приложение не должно ходить через собственный туннель:
                // иначе соединение sing-box к серверу замкнётся само на себя.
                // Дублирует ProtectCallback (per-socket) на уровне UID (весь процесс) —
                // не конфликт, а вторая независимая линия защиты от той же петли.
                addDisallowedApplication(packageName)
                applyDisallowedApps(this)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setMetered(false)
            }
            .establish()
    } catch (e: Throwable) {
        Log.e(TAG, "buildVpnInterface: $e")
        null
    }

    /**
     * Исключает выбранные пользователем приложения из VPN на уровне ОС.
     *
     * Зачем отдельно от bypass-доменов. Bypass — это policy-routing ВНУТРИ туннеля: пакет
     * уже попал в TUN, и sing-box решает отправить его напрямую. Для системы VPN при этом
     * остаётся активным, и приложение через `ConnectivityManager.getNetworkCapabilities()`
     * видит `TRANSPORT_VPN`. Сервисы, которые отказываются работать при любых признаках
     * VPN/прокси (госуслуги, банки, платёжные сервисы, маркетплейсы), смотрят именно на это
     * — поэтому байпас по домену им не помогал: трафик шёл напрямую, а приложение всё равно
     * видело активный VPN и отказывалось работать. `addDisallowedApplication` исключает
     * приложение из туннеля целиком: `getActiveNetwork()` возвращает ему настоящую сеть.
     *
     * Список — пользовательский и общий, без привязки к конкретному сервису: у каждого свой
     * набор таких приложений, и он меняется чаще, чем выходят сборки.
     *
     * Отказ по КАЖДОМУ пакету ловится отдельно: приложение могло быть удалено с момента
     * добавления в список, а `NameNotFoundException` из `addDisallowedApplication` иначе
     * уронил бы сборку всего интерфейса — то есть одно удалённое приложение оставило бы
     * пользователя вообще без VPN.
     *
     * Ограничение, о котором надо говорить честно (оно отражено в тексте UI): исключение
     * снимает признак «VPN активен на моей сети», но НЕ прячет VPN полностью — интерфейс
     * tun0 остаётся виден через `NetworkInterface.getNetworkInterfaces()`, пакет APF виден
     * `PackageManager`, иконка VPN остаётся в статус-баре. Без root это неустранимо.
     */
    private fun applyDisallowedApps(builder: Builder) {
        val packages = try {
            val raw = ApfCore.disallowedAppsJson()
            val arr = org.json.JSONArray(raw)
            (0 until arr.length()).mapNotNull { arr.optString(it, null) }
        } catch (e: Throwable) {
            Log.w(TAG, "вне VPN: не удалось прочитать список приложений: $e")
            return
        }
        if (packages.isEmpty()) return

        var applied = 0
        for (pkg in packages) {
            if (pkg.isBlank() || pkg == packageName) continue
            try {
                builder.addDisallowedApplication(pkg)
                applied++
            } catch (e: PackageManager.NameNotFoundException) {
                // Приложение удалено с устройства — пропускаем молча-но-с-логом, список
                // чистить здесь не будем: пользователь мог удалить его временно.
                Log.w(TAG, "вне VPN: пакет не найден, пропущен: $pkg")
            } catch (e: Throwable) {
                Log.w(TAG, "вне VPN: не удалось исключить $pkg: $e")
            }
        }
        ApfFileLogger.log("I", TAG, "вне VPN: исключено приложений — $applied из ${packages.size}")
    }

    /**
     * Задача #11, вариант 2 (2026-08-17). Вызывается ИЗ Go (androidbridge.TunFdCallback)
     * на каждом emergencySwitch/ручном переподключении, пока VPN-режим активен — не из
     * UI-потока, а из горутины движка; тот же класс вызова, что и уже используемый отсюда
     * же protect() (ProtectCallback), Builder().establish() не требует главного потока.
     *
     * Пересоздаёт системный TUN-интерфейс тем же кодом, что и первый запуск
     * (buildVpnInterface — Android заменяет МАРШРУТИЗАЦИЮ на новый интерфейс, "seamless
     * handover", прежний fd остаётся открытым, пока Go explicitly его не закроет — см.
     * androidbridge.tun.go/swapHeldTunFd), и передаёт новый fd Go-слою тем же способом,
     * что и startVpn выше — detachFd(), владение переходит безвозвратно.
     *
     * closeTun()/vpnInterface здесь так же не участвуют, как и в startVpn (см. комментарий
     * там): этот путь никогда не заполняет vpnInterface реальным pfd.
     *
     * @return новый fd (> 0) или -1, если Builder().establish() отказал (например,
     *         VPN-разрешение отозвано пользователем между переключениями) — Go-сторона
     *         (tunRunner.ReloadWithFreshTun) обязана трактовать любое значение <= 0 как
     *         отказ и не трогать уже работающее соединение.
     */
    private fun requestTunFd(): Int {
        val pfd = buildVpnInterface() ?: return -1
        return pfd.detachFd()
    }

    // ─── Роль «Выход» (Э-Выход-2, docs/PLAN_APF_VHOD_VYHOD_v1.0.md) ────────────
    //
    // НЕЗАВИСИМЫЙ от currentState/currentMode жизненный цикл: устройство может
    // одновременно быть «Входом» (режимы выше) и «Выходом» (эта секция) — ТЗ §1 требует,
    // чтобы включение одной роли не предполагало выключения другой. Поэтому эта секция
    // не читает и не пишет currentState/currentMode, а источник истины о том, работает
    // ли роль «Выход», — всегда живой ApfCore.isServerRoleRunning() (androidServerRunner.
    // IsRunning() → CommandServer.Instance() в Go-слое), не отдельный Kotlin-флаг.
    //
    // Роль «Выход» не создаёт TUN (ServerDoc не содержит tun-инбаунда — OpenTun() у
    // PlatformInterface никогда не вызывается для этого пути, см.
    // internal/singbox/android_server_runner.go), но требует ProtectCallback: тот же
    // унаследованный VpnService.protect(fd), что и клиентский путь выше — работает вне
    // зависимости от того, установлен ли TUN этим же экземпляром службы (protect() не
    // требует активного tun-интерфейса, это отдельная возможность VpnService).
    private suspend fun startServerRole(
        port: Int,
        realityDest: String,
        identityJson: String,
        maxClients: Int = 0,
        relayAddr: String = "",
        relayFingerprint: String = "",
    ) =
        withContext(Dispatchers.IO) {
            if (!engineReady) {
                broadcastServerRoleState(false, "ядро не инициализировано")
                return@withContext
            }
            if (port !in 1..65535) {
                broadcastServerRoleState(false, "порт $port вне диапазона 1..65535")
                return@withContext
            }
            if (identityJson.isEmpty()) {
                broadcastServerRoleState(false, "identity обязателен (см. generateServerIdentityJson)")
                return@withContext
            }

            ApfCore.setServerProtectCallback { fd -> protect(fd) }

            val err = try {
                ApfCore.startServerRole(port, realityDest, identityJson, maxClients, relayAddr, relayFingerprint)
            } catch (e: Throwable) {
                "$e"
            }
            if (err.isNotEmpty()) {
                Log.e(TAG, "startServerRole: $err")
                ApfFileLogger.log("E", TAG, "startServerRole(port=$port): $err")
                broadcastServerRoleState(false, err)
                return@withContext
            }

            val relayPart = if (relayAddr.isNotEmpty()) ", relay-fallback: $relayAddr" else ""
            Log.i(TAG, "роль «Выход» запущена на порту $port$relayPart")
            ApfFileLogger.log("I", TAG, "startServerRole: роль «Выход» запущена на порту $port$relayPart")
            broadcastServerRoleState(true, "")
        }

    private suspend fun stopServerRole() = withContext(Dispatchers.IO) {
        stopServerRoleQuietly()
        broadcastServerRoleState(false, "")
        // Симметрично stopEverything(): не оставляем службу висеть на переднем плане
        // без единого активного пути, если клиент тоже сейчас не подключён.
        forceStopServiceIfIdle()
    }

    /** Тихий вариант — без broadcast, для путей, где служба и так уничтожается целиком
     * (onDestroy, воскрешение без намерения): бросать событие в UI, которого уже не
     * будет, бессмысленно, а ошибку — потерять нельзя, поэтому лог остаётся. */
    private fun stopServerRoleQuietly() {
        try {
            val err = ApfCore.stopServerRole()
            if (err.isNotEmpty()) Log.w(TAG, "stopServerRole: $err")
        } catch (e: Throwable) {
            Log.w(TAG, "stopServerRole: $e")
        }
    }

    private fun isServerRoleRunning(): Boolean =
        try { ApfCore.isServerRoleRunning() } catch (e: Throwable) { false }

    private fun broadcastServerRoleState(running: Boolean, message: String) {
        val intent = Intent(BROADCAST_SERVER_ROLE_STATE).apply {
            setPackage(packageName)
            putExtra(EXTRA_SERVER_RUNNING, running)
            putExtra(EXTRA_SERVER_MESSAGE, message)
        }
        sendBroadcast(intent)
    }

    // ─── Остановка ────────────────────────────────────────────────────────────

    private suspend fun stopEverything() = withContext(Dispatchers.IO) {
        if (currentState != State.IDLE || currentMode != Mode.NONE) {
            setState(State.DISCONNECTING, "")
            statusJob?.cancel()
            statusJob = null

            // Отказ обратимой остановки нельзя проглатывать: если ядро не сняло сетевые
            // изменения, снимок состояния телефона после сеанса разойдётся с исходным,
            // и причину нужно видеть в логе, а не выяснять по разнице снимков.
            //
            // VPN-режим останавливается через stopTun (закрывает и TUN-дескриптор, и
            // InProcessRunner), режим «прокси» — через disconnect. Оба идут ОБРАТИМОЙ
            // дорогой (урок D-A17): следующий Connect/StartTun в этом же сеансе службы
            // обязан снова сработать.
            val err = try {
                if (currentMode == Mode.VPN) ApfCore.stopTun() else ApfCore.disconnect()
            } catch (e: Throwable) {
                "$e"
            }
            if (err.isNotEmpty()) Log.e(TAG, "disconnect: $err")

            closeTun()

            currentMode = Mode.NONE
            setState(State.IDLE, "")
        }

        // Снятие с переднего плана — на ЛЮБОМ пути выхода, включая ранний. Иначе служба,
        // поднятая startForeground в onStartCommand, остаётся висеть уже без сеанса.
        //
        // Э-Выход-2: НЕ безусловно — если роль «Выход» в этот момент активна (независимый
        // жизненный цикл, см. секцию выше), «Отключить» на клиентском экране не обязано
        // молча гасить её тоже. forceStopServiceIfIdle() проверяет оба независимых пути.
        forceStopServiceIfIdle()
    }

    /** Останавливает Android-службу целиком, если НИ ОДИН из двух независимых путей
     * (клиент currentMode, роль «Выход» isServerRoleRunning()) сейчас не активен. */
    private fun forceStopServiceIfIdle() {
        if (currentMode == Mode.NONE && !isServerRoleRunning()) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /** Безусловная остановка службы — только для путей, где сохранять что-либо уже
     * бессмысленно (воскрешение без намерения, неизвестное действие): оба независимых
     * пути к этому моменту уже остановлены вызывающей стороной. */
    private fun forceStopService() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** Закрытие TUN отдельным методом: дескриптор нельзя терять ни на одном пути выхода. */
    private fun closeTun() {
        val fd = vpnInterface ?: return
        vpnInterface = null
        try {
            fd.close()
        } catch (e: Throwable) {
            Log.e(TAG, "closeTun: $e")
        }
    }

    // ─── Наблюдение за состоянием ─────────────────────────────────────────────

    /**
     * Ждёт, пока движок не подтвердит РАБОЧИЙ канал узла (isConnected() И isVerified()),
     * а не просто поднятый сокет sing-box (isConnected() один). Один общий предел
     * CONNECT_TIMEOUT_MS на обе фазы разом (подбор узла + проверка канала) — не отдельные
     * тайм-ауты на каждую, иначе потолок ожидания стал бы вдвое длиннее задокументированного
     * выше (2 мин 12 с реального ожидания рабочего узла на устройстве).
     *
     * Промежуточное состояние VERIFYING показывается вместо CONNECTED, пока канал не
     * подтверждён — раньше служба объявляла CONNECTED сразу по isConnected(), хотя это
     * значит только "sing-box поднялся", не "узел реально пропускает трафик". Живой лог
     * пользователя из России (2026-08-20) показал ровно этот разрыв: экран "подключено",
     * Chrome не грузит ни одной страницы, а движок в фоне ещё несколько десятков секунд
     * перебирает узлы, пока не найдёт рабочий (см. apf-russia-nodes-no-internet в памяти
     * проекта). Пользователь в этом окне обоснованно решал, что подключение не работает, и
     * переподключался вручную — что сбрасывало уже идущее автовосстановление.
     */
    /**
     * Исход ожидания. Различать три состояния обязательно: «туннель есть, но подтвердить
     * канал не удалось» — это НЕ отказ, и рвать его нельзя (см. UNVERIFIED).
     */
    private enum class ConnectOutcome {
        /** Канал подтверждён сквозной проверкой — полноценное «Подключено». */
        VERIFIED,

        /**
         * sing-box поднят, но подтвердить сквозной трафик не удалось за отведённое время.
         *
         * Раньше это трактовалось как полный отказ: служба звала stopTun() и показывала
         * «не удалось подключиться». Это ошибка, причём разрушительная (найдено ревью
         * 2026-08-24). Подтверждение опирается на ОДНУ внешнюю пробу, и есть ветки, где она
         * не повторяется вовсе — при выключенном автопереключении и в sticky-окне после
         * ручного выбора. То есть рабочий туннель, который watchdog всё это время считает
         * здоровым, гарантированно сносился через 180 секунд, и повторная попытка давала то
         * же самое — детерминированный тупик ровно для того пользователя, ради которого
         * фича и делалась. Правильное поведение — оставить соединение и честно сказать, что
         * канал не подтверждён.
         */
        UNVERIFIED,

        /** Туннель не поднялся вовсе — вот это настоящий отказ. */
        FAILED,
    }

    /**
     * Запускает попытку подключения, гарантируя, что одновременно живёт не больше одной.
     * Предыдущая (возможно, всё ещё ждущая подтверждения канала) отменяется — см. connectJob.
     */
    private fun startAttempt(block: suspend () -> Unit) {
        val previous: Job?
        val job = launch(start = kotlinx.coroutines.CoroutineStart.LAZY) { block() }
        synchronized(connectJobMu) {
            previous = connectJob
            connectJob = job
        }
        previous?.cancel()
        job.start()
    }

    /** Отменяет текущую попытку подключения, если она есть. */
    private fun cancelConnectAttempt() {
        val job: Job?
        synchronized(connectJobMu) {
            job = connectJob
            connectJob = null
        }
        job?.cancel()
    }

    private suspend fun awaitVerifiedConnection(): ConnectOutcome {
        val slowAt = System.currentTimeMillis() + CONNECT_SLOW_MS
        val deadline = System.currentTimeMillis() + CONNECT_TIMEOUT_MS
        var slowNoticed = false
        var verifyingNoticed = false
        while (System.currentTimeMillis() < deadline && !(ApfCore.isConnected() && ApfCore.isVerified())) {
            if (!verifyingNoticed && ApfCore.isConnected()) {
                verifyingNoticed = true
                setState(State.VERIFYING, "узел на связи, проверяю канал")
            }
            if (!slowNoticed && System.currentTimeMillis() >= slowAt) {
                slowNoticed = true
                if (verifyingNoticed) {
                    setState(State.VERIFYING, "проверка затянулась — узел может быть нерабочим, ищу замену")
                } else {
                    setState(State.CONNECTING, "подбор затянулся — продолжаю перебор серверов")
                }
            }
            delay(POLL_INTERVAL_MS)
        }
        return when {
            ApfCore.isConnected() && ApfCore.isVerified() -> ConnectOutcome.VERIFIED
            ApfCore.isConnected() -> ConnectOutcome.UNVERIFIED
            else -> ConnectOutcome.FAILED
        }
    }

    /**
     * Прежняя версия при потере связи вызывала startVpn() рекурсивно из собственной
     * корутины и не закрывала прежний дескриптор (дефект D-A6): за несколько
     * переподключений накапливались утечки fd, и испытание на 100 циклов теряло смысл.
     * Здесь монитор только фиксирует потерю и завершает сеанс — решение о повторе
     * принимает вызывающая сторона.
     */
    private fun startStatusMonitor() {
        statusJob?.cancel()
        statusJob = launch {
            while (isActive && currentState == State.CONNECTED) {
                delay(5_000)
                // Дефект D6: монитор читал из этого же JSON ТОЛЬКО `connected`, хотя признак
                // подтверждения канала лежит рядом. Деградация «подтверждён → не подтверждён»
                // (узел перестал пропускать трафик, а сокет sing-box жив) не порождает
                // ни одного события и была для пользователя невидима — экран и уведомление
                // держали зелёное «Подключено» до конца сеанса.
                // Один разбор на все три величины: лишний вызов моста здесь — это ещё один
                // переход Kotlin→Go на каждом тике монитора, без всякой нужды.
                val snapshot = try {
                    val js = JSONObject(ApfCore.stateJson())
                    val connected = js.optBoolean("connected", false)
                    Triple(
                        connected,
                        normalizeVerifyState(
                            js.optString("verify_state", ""),
                            connected,
                            js.optBoolean("verified", false)
                        ),
                        js.optInt("active_verified_latency_ms", 0)
                    )
                } catch (e: Throwable) {
                    Log.e(TAG, "разбор состояния: $e")
                    continue
                }
                val (connected, verify, latency) = snapshot
                if (!connected) {
                    Log.w(TAG, "связь с узлом потеряна")
                    setState(State.ERROR, "связь с узлом потеряна")
                    return@launch
                }
                if (verify != currentVerifyState || latency != currentVerifiedLatency) {
                    val previous = currentVerifyState
                    currentVerifyState = verify
                    currentVerifiedLatency = latency
                    if (verify != previous) {
                        Log.i(TAG, "состояние канала: $previous → $verify")
                        ApfFileLogger.log("I", TAG, "состояние канала: $previous → $verify")
                    }
                    // Дефект D3 + D5: перевыпуск уведомления и повторный бродкаст — иначе
                    // и шторка, и экран остаются на снимке момента подключения.
                    refreshNotification()
                    broadcastState()
                }
            }
        }
    }

    // ─── Состояние и уведомления ──────────────────────────────────────────────

    private fun setState(state: State, message: String) {
        currentState = state
        lastMessage = message
        if (message.isNotEmpty()) Log.i(TAG, "$state: $message")
        // Признак подтверждения обновляем ВМЕСТЕ с состоянием, а не когда-нибудь потом:
        // и бродкаст, и уведомление ниже обязаны нести один и тот же снимок (D5).
        refreshVerifyState()
        refreshNotification()
        broadcastState()
    }

    /** Снимает текущее состояние проверки канала у ядра. IDLE/DISCONNECTING — заведомо
     * «Отключено», спрашивать ядро незачем (и нечего: сеанса нет). */
    private fun refreshVerifyState() {
        if (!engineReady || currentState == State.IDLE || currentState == State.DISCONNECTING) {
            currentVerifyState = VERIFY_IDLE
            currentVerifiedLatency = 0
            return
        }
        currentVerifyState = try {
            ApfCore.verifyState()
        } catch (e: Throwable) {
            Log.w(TAG, "состояние канала: $e")
            // Не «Отключено»: туннель в этот момент может быть поднят, и молчаливый откат
            // к idle показал бы отсутствие сеанса поверх работающего соединения.
            if (currentState == State.CONNECTED || currentState == State.VERIFYING) VERIFY_CHECKING else VERIFY_IDLE
        }
        currentVerifiedLatency = safeVerifiedLatency()
    }

    private fun broadcastState() {
        val intent = Intent(BROADCAST_STATE).apply {
            setPackage(packageName)   // широковещание только внутри приложения
            // D9: «подключено» — только подтверждённый канал. Факт живого сеанса едет
            // отдельным полем, чтобы «Отключить»/«Сменить сервер» работали и на
            // неподтверждённом туннеле (рвать его нельзя — см. ConnectOutcome.UNVERIFIED).
            putExtra(EXTRA_CONNECTED, currentState == State.CONNECTED && currentVerifyState == VERIFY_VERIFIED)
            putExtra(EXTRA_SESSION_ACTIVE, currentState == State.CONNECTED)
            putExtra(EXTRA_VERIFY_STATE, currentVerifyState)
            putExtra(EXTRA_VERIFIED_LATENCY, currentVerifiedLatency)
            putExtra(EXTRA_NODE_NAME, safeNodeName())
            putExtra(EXTRA_LATENCY, safeLatency())
            putExtra(EXTRA_STATE, currentState.name)
            putExtra(EXTRA_MESSAGE, lastMessage)
        }
        sendBroadcast(intent)
    }

    private fun safeNodeName(): String =
        if (!engineReady) "" else try { ApfCore.activeNodeName() } catch (e: Throwable) { "" }

    private fun safeLatency(): Int =
        if (!engineReady) 0 else try { ApfCore.activeNodeLatency() } catch (e: Throwable) { 0 }

    /** D12: задержка по сквозной HTTP-проверке. 0 — такого замера не было (C-20: не обязательно TUN). */
    private fun safeVerifiedLatency(): Int =
        if (!engineReady) 0 else try { ApfCore.activeNodeVerifiedLatency() } catch (e: Throwable) { 0 }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(CHANNEL_ID, "APF", NotificationManager.IMPORTANCE_LOW)
        channel.description = "Состояние подключения APF"
        channel.setShowBadge(false)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    /**
     * Перевыпуск постоянного уведомления (дефект D3).
     *
     * До этого уведомление собиралось трижды за сеанс — в onStartCommand и сразу после
     * успешного подключения в каждом из двух режимов — и НИ РАЗУ не читало признак
     * подтверждения канала. «APF: прокси активен» висело в шторке до конца сеанса
     * независимо от того, что происходило с трафиком: узел мог умереть через минуту, а
     * шторка — единственный UI, видимый при свёрнутом приложении — продолжала утверждать,
     * что всё в порядке.
     *
     * Отдельным методом, а не строкой в двух местах: точек, откуда состояние может
     * измениться, теперь три (setState, монитор состояния, смена узла движком).
     */
    private fun refreshNotification() {
        // startForeground ещё не звался — уведомление некому будет снять (stopForeground
        // работает только над foreground-уведомлением службы).
        if (!foregroundStarted) return
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
        } catch (e: Throwable) {
            Log.w(TAG, "перевыпуск уведомления: $e")
        }
    }

    /**
     * Заголовок уведомления. Тексты состояний канала — ДОСЛОВНО те же, что на главном
     * экране и в веб-интерфейсе (общий контракт, см. verifyStateText в ApfCore.kt):
     * пользователь не должен видеть в шторке одно, а в приложении — другое.
     */
    private fun notificationTitle(): String = when (currentState) {
        State.CONNECTED -> "APF: " + verifyStateText(currentVerifyState)
        State.VERIFYING -> "APF: " + verifyStateText(VERIFY_CHECKING)
        State.ERROR -> "APF: ошибка"
        State.CONNECTING -> "APF: подключение"
        State.DISCONNECTING -> "APF: отключение"
        // IDLE. До первого startForeground это стартовое уведомление службы, которая прямо
        // сейчас начинает подключение (прежний текст, менять нельзя — это тот самый вызов,
        // что удерживает контракт 5 секунд). После — сеанса действительно нет.
        else -> if (foregroundStarted) "APF: " + verifyStateText(VERIFY_IDLE) else "APF: подключение"
    }

    private fun buildNotification(): Notification {
        val disconnectPending = PendingIntent.getService(
            this, 0,
            Intent(this, APFVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val openPending = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val node = safeNodeName().ifEmpty { "…" }
        val latency = safeLatency()
        // Найдено консилиумом 2026-08-24: уведомление — единственный UI, постоянно видимый
        // при свёрнутом приложении, и раньше оно ничего не говорило про приложения вне VPN —
        // тот же пробел, что и на главном экране (см. updateDisallowedAppsIndicator в
        // MainActivity.kt), только здесь он ещё заметнее: пользователь чаще смотрит в шторку
        // уведомлений, чем открывает само приложение.
        val disallowedCount = try {
            org.json.JSONArray(ApfCore.disallowedAppsJson()).length()
        } catch (e: Throwable) {
            0
        }
        val disallowedSuffix = if (disallowedCount > 0) " · $disallowedCount мимо VPN" else ""

        // D12: две задержки — РАЗНЫЕ величины, и подписаны они по-разному.
        // «TCP» — рукопожатие до порта, которое проходит и у узла, не пропускающего ничего.
        //
        // C-20 (ТЗ v1.4): слово «через туннель» БОЛЬШЕ НЕ ставится вслепую. Живой прогон:
        // экран писал «N мс через туннель», а лог движка в тот же момент честно говорил, что
        // замер сделан через SOCKS5 и системный TUN-путь для сторонних приложений он не
        // подтверждает; в режиме «Прокси» TUN нет вовсе, а надпись была та же. Источник
        // замера теперь спрашивается у моста.
        val latencyPart = if (currentVerifiedLatency > 0) {
            when (ApfCore.activeNodeVerifiedLatencySource()) {
                VERIFIED_VIA_TUN -> " · $currentVerifiedLatency мс через туннель"
                VERIFIED_VIA_SOCKS -> " · $currentVerifiedLatency мс через прокси-канал узла"
                else -> " · $currentVerifiedLatency мс до выхода"
            }
        } else if (latency > 0) {
            " · $latency мс до сервера (TCP)"
        } else {
            ""
        }
        val body = when (currentState) {
            State.CONNECTED, State.VERIFYING -> "$node$latencyPart$disallowedSuffix"
            State.ERROR -> lastMessage.ifEmpty { "нет подключения" }
            State.IDLE, State.DISCONNECTING ->
                if (foregroundStarted) "нет активного подключения" else "Подбираю сервер$disallowedSuffix"
            else -> "Подбираю сервер$disallowedSuffix"
        }

        // C-8 (ТЗ v1.4, UI_CONTRACT §5.5): предупреждение о недостающей системной настройке —
        // ТЕМ ЖЕ ТЕКСТОМ, что и короткая строка у статуса на экране, а не отдельной
        // формулировкой. Уходит в BigTextStyle, потому что в одну строку шторки оно не влезет
        // и было бы обрезано (та же причина, по которой длинные ошибки не показываются toast).
        val ksWarning = if (needsSystemKsWarning()) getString(R.string.ks_status_warn) else ""
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(notificationTitle())
            .setContentText(if (ksWarning.isEmpty()) body else "$body\n$ksWarning")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openPending)
            .addAction(android.R.drawable.ic_delete, "Отключить", disconnectPending)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
        if (ksWarning.isNotEmpty()) {
            builder.setStyle(NotificationCompat.BigTextStyle().bigText("$body\n$ksWarning"))
            // Действие уведомления — тот же системный экран VPN, что и кнопка на экране
            // (UI_CONTRACT §5.5). Три кандидата, как в MainActivity.openSystemVpnSettings,
            // здесь не строятся: PendingIntent можно завести только один, а ACTION_VPN_SETTINGS
            // есть с API 24 и на устройстве приёмки работает (живой прогон A2 PASS).
            val vpnSettingsPending = PendingIntent.getActivity(
                this, 1,
                Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(
                android.R.drawable.ic_menu_preferences,
                "Настройки VPN",
                vpnSettingsPending
            )
        }
        return builder.build()
    }

    /**
     * C-9: отдельное (не постоянное) уведомление с честной причиной вынужденной смены
     * режима на старте. Отдельное, а не текст в основном, — потому что основное живёт весь
     * сеанс и через секунду переписывается состоянием подключения, а эту причину надо
     * прочитать один раз и закрыть.
     */
    private fun showStartNoticeNotification(notice: String) {
        try {
            val openPending = PendingIntent.getActivity(
                this, 2,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val n = NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("APF: режим изменён при автозапуске")
                .setContentText(notice)
                .setStyle(NotificationCompat.BigTextStyle().bigText(notice))
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(openPending)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .build()
            getSystemService(NotificationManager::class.java).notify(NOTIF_ID + 2, n)
        } catch (e: Throwable) {
            Log.w(TAG, "уведомление о смене режима: $e")
        }
    }

    private fun showLeakNotification(leakType: String, details: String) {
        // C-19 (UI_CONTRACT §5.3): подтверждение чек-листа «Я включил, скрыть» снимается
        // РОВНО ЗДЕСЬ — оранжевое предупреждение о системной защите возвращается только
        // тогда, когда APF САМ обнаружил реальную утечку, а не по таймеру и не при каждом
        // возврате на экран. Обратное (возвращать шум периодически) обесценило бы кнопку.
        try {
            getSharedPreferences(MainActivity.UI_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(MainActivity.KEY_KS_CHECKLIST_ACK, false).apply()
            refreshNotification()
        } catch (e: Throwable) {
            Log.w(TAG, "сброс подтверждения чек-листа Kill Switch: $e")
        }
        val n = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APF: обнаружена утечка")
            .setContentText("[$leakType] $details")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID + 1, n)
    }

    // ─── Доступ из MainActivity через Binder ──────────────────────────────────

    fun getState() = currentState
    fun getMode() = currentMode
    fun getMessage() = lastMessage

    // Экран обязан показывать, какой узел выбран: без этого по журналу испытания
    // невозможно понять, к чему именно относится измеренная задержка (дефект D-A21).
    fun getNodeName() = safeNodeName()
    fun getLatency() = safeLatency()

    /** D12: задержка по сквозной HTTP-проверке; 0 — такого замера не было (C-20: не обязательно TUN). */
    fun getVerifiedLatency() = currentVerifiedLatency

    /** idle | checking | verified | failed — то, что экран показывает пользователю (D4). */
    fun getVerifyState() = currentVerifyState

    fun isReady() = engineReady

    /**
     * Сеанс живёт: туннель/прокси подняты, есть что отключать и есть на чём переключать
     * узел. О ПОДТВЕРЖДЁННОСТИ канала не говорит ничего.
     *
     * Именно это значение нужно кнопкам «Отключить»/«Сменить сервер»/«Подключить другой
     * узел»: неподтверждённый туннель — не повод отказывать в переключении, наоборот,
     * ровно тогда переключение и нужно.
     */
    fun isSessionActive() = currentState == State.CONNECTED

    /**
     * Дефект D9: подключение, за которое можно ручаться, — только подтверждённое.
     *
     * Прежде здесь стояло `currentState == State.CONNECTED`, а это состояние объявляется и
     * при исходе UNVERIFIED — то есть служба сообщала «подключено» про канал, через который
     * не открывался ни один сайт. Само решение НЕ рвать такой туннель остаётся (см.
     * ConnectOutcome.UNVERIFIED): изменено только утверждение, а не поведение.
     */
    fun isConnected() = currentState == State.CONNECTED && currentVerifyState == VERIFY_VERIFIED
    fun getStatsJSON() = if (engineReady) ApfCore.statsJson() else "{}"
    fun getNodesJSON() = if (engineReady) ApfCore.nodesJson() else "[]"
    fun addNode(link: String) = if (engineReady) ApfCore.addNode(link) else "ядро не инициализировано"
    fun forceSwitch() { if (engineReady) ApfCore.forceSwitch() }
    fun refreshSystemKillSwitch() = publishSystemKillSwitchState()
}
