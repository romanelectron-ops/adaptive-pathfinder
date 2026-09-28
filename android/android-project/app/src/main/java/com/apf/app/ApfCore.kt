package com.apf.app

import androidbridge.Androidbridge
import androidbridge.LeakCallback
import androidbridge.LogCallback
import androidbridge.ProtectCallback
import androidbridge.StateCallback
import androidbridge.TunFdCallback

// ─── Общий контракт «проверенности» для всех трёх UI (2026-09-06) ─────────────────────────
//
// Тот же набор значений и те же ТЕКСТЫ, что показывает веб-интерфейс: расхождение здесь —
// это расхождение в том, что пользователь понимает под «подключено», между телефоном и ПК.
// Источник истины — internal/models/node.go (константы Verify*/Badge*), сюда они попадают
// строками через JSON моста, поэтому продублированы как строковые константы, а не enum.
//
// СМЫСЛ, который нельзя исказить при правках: «трафик проходил» относится ТОЛЬКО к узлу,
// через который реально подключались. Обычное сканирование пула делает лишь TCP-дозвон,
// поэтому у подавляющего большинства узлов честный значок — жёлтый tcp_alive, и он означает
// «через этот узел трафик не проверялся», а НЕ «трафика нет».

/** Не подключено. */
const val VERIFY_IDLE = "idle"

/** Туннель поднят, сквозная проверка канала идёт, провала ещё не было. */
const val VERIFY_CHECKING = "checking"

/** Канал подтверждён HTTP-проверкой ЧЕРЕЗ туннель — единственное честное «Подключено». */
const val VERIFY_VERIFIED = "verified"

/** Туннель поднят, но канал признан неработающим. Соединение при этом НЕ рвётся (см.
 * APFVpnService.ConnectOutcome.UNVERIFIED) — меняется только то, что видит пользователь. */
const val VERIFY_FAILED = "failed"

/**
 * Приводит значение к одному из четырёх состояний контракта.
 *
 * Пустая строка — не «неизвестно»: поле `verify_state` появилось 2026-09-06 и наполняется
 * отдельным слоем движка, а до того у моста есть только два булевых. Пусто трактуем как
 * `idle`, если не подключено, и как `checking`, если подключено — иначе на неполной сборке
 * экран показал бы «Отключено» поверх живого туннеля.
 */
fun normalizeVerifyState(raw: String, connected: Boolean = false, verified: Boolean = false): String =
    when (raw) {
        VERIFY_IDLE, VERIFY_CHECKING, VERIFY_VERIFIED, VERIFY_FAILED -> raw
        else -> when {
            verified -> VERIFY_VERIFIED
            connected -> VERIFY_CHECKING
            else -> VERIFY_IDLE
        }
    }

/** Текст статуса. Обязан совпадать с веб-интерфейсом ДОСЛОВНО. */
fun verifyStateText(state: String): String = when (state) {
    VERIFY_CHECKING -> "Проверяю канал…"
    VERIFY_VERIFIED -> "Подключено"
    VERIFY_FAILED -> "Туннель поднят, но трафик не идёт"
    else -> "Отключено"
}

// ─── C-13 (ТЗ v1.4): тумблеры защиты — ТРИ состояния, а не два ───────────────────────────
//
// Живой прогон K8-LIVE B2 (FAIL): движок на Android поднимается только при подключении,
// поэтому старые bool-геттеры на свежем старте возвращали false — и экран рисовал ВЫКЛ над
// защитой, которая в config.json стоит ВКЛ. «Не знаю» показывалось как «выключено».
// Мост (лот L1b-ENG2) отвечает теперь строкой: on | off | unknown, плюс сводка
// GetProtectionStateJSON с признаком known и источником (engine | config).

/** Тумблер включён (по данным ядра). */
const val TOGGLE_ON = "on"

/** Тумблер выключен (по данным ядра). */
const val TOGGLE_OFF = "off"

/** Ядро не запущено — истинное положение через живой движок узнать нельзя. */
const val TOGGLE_UNKNOWN = "unknown"

// Имена тумблеров для [ApfCore.toggleState] — дословно строки моста
// (androidbridge.ToggleIPv6Block и соседние константы bridge.go).
const val TOGGLE_IPV6_BLOCK = "ipv6_block"
const val TOGGLE_WEBRTC_BLOCK = "webrtc_block"
const val TOGGLE_CYCLIC_SEARCH = "cyclic_search"
const val TOGGLE_NODE_AUTO_SWITCH = "node_auto_switch"
const val TOGGLE_CHAIN_MODE = "chain_mode"
const val TOGGLE_MULTIHOP = "multihop"

// ─── C-20 (ТЗ v1.4): чем получен замер задержки ──────────────────────────────────────────
//
// «Через туннель» допустимо говорить ТОЛЬКО про TUN-bound пробу (models.VerifiedViaTUN):
// замер через локальный SOCKS5 доказывает, что канал sing-box до узла жив, и НЕ доказывает,
// что трафик сторонних приложений идёт через системный TUN. В режиме «Прокси» TUN нет вовсе.

/** Замер сделан через локальный SOCKS5 движка. */
const val VERIFIED_VIA_SOCKS = "socks5"

/** Замер сделан прямой пробой мимо SOCKS — тем же путём, что у браузера. */
const val VERIFIED_VIA_TUN = "tun"

/** Значки узла в списках (models.Node.VerifyBadge). */
const val BADGE_PROVEN_FRESH = "proven_fresh"
const val BADGE_PROVEN_STALE = "proven_stale"
const val BADGE_PROVEN_FAILED = "proven_failed"
const val BADGE_TCP_ALIVE = "tcp_alive"
const val BADGE_DEAD = "dead"
const val BADGE_UNCHECKED = "unchecked"

fun verifyBadgeIcon(badge: String): String = when (badge) {
    BADGE_PROVEN_FRESH -> "✅"
    BADGE_PROVEN_STALE -> "🟢"
    BADGE_PROVEN_FAILED -> "⚠️"
    BADGE_TCP_ALIVE -> "🟡"
    BADGE_DEAD -> "🔴"
    else -> "⚪"
}

/** Подпись к значку. Жёлтый — «не проверялось», а не «трафика нет»: смешивать нельзя. */
fun verifyBadgeText(badge: String): String = when (badge) {
    BADGE_PROVEN_FRESH -> "Трафик проходил недавно"
    BADGE_PROVEN_STALE -> "Трафик проходил, но давно"
    BADGE_PROVEN_FAILED -> "Раньше пропускал, последняя проверка — сбой"
    BADGE_TCP_ALIVE -> "Отвечает по TCP, трафик не проверялся"
    BADGE_DEAD -> "Не отвечает"
    else -> "Не проверен"
}

/**
 * ApfCore — единственная точка соприкосновения приложения с Go-ядром.
 *
 * Зачем прослойка. `gomobile bind` сам решает, как назвать сгенерированные Java-методы:
 * экспортированные функции Go получают имя с маленькой буквы (`Init` → `init`,
 * `GetStateJSON` → `getStateJSON`). Прежний код звал `Androidbridge.Init(...)` с большой
 * буквы и вдобавок вовсе не импортировал мост — оба Kotlin-файла не компилировались
 * (дефект D-A1).
 *
 * ПРОВЕРИТЬ НА ЭТАПЕ Э-1. После первой сборки apf.aar откройте сгенерированный
 * `androidbridge/Androidbridge.java` внутри архива и сверьте имена. Если регистр окажется
 * иным — правка нужна ТОЛЬКО здесь, остальной код к именам моста не привязан.
 */
object ApfCore {

    // ─── Жизненный цикл ───────────────────────────────────────────────────────

    /**
     * @param dataDir      getFilesDir().absolutePath
     * @param nativeLibDir applicationInfo.nativeLibraryDir — единственный каталог, откуда
     *                     Android 10+ разрешает выполнять файлы; там лежит libsingbox.so
     * @return пустая строка при успехе, иначе текст ошибки
     */
    fun init(dataDir: String, nativeLibDir: String): String =
        Androidbridge.init(dataDir, nativeLibDir)

    fun shutdown() = Androidbridge.shutdown()

    fun version(): String = Androidbridge.version()

    // ─── Подключение ──────────────────────────────────────────────────────────

    fun connect(): String = Androidbridge.connect()

    fun connectNode(link: String): String = Androidbridge.connectNode(link)

    /**
     * Завершает сеанс, оставляя ядро готовым к следующему подключению.
     *
     * @return пустая строка при успехе, иначе текст ошибки. Возвращаемое значение
     *         появилось вместе с исправлением D-A17: прежде мост звал терминальный
     *         engine.Stop(), после которого повторное подключение в том же сеансе
     *         приложения было невозможно, и отказ было нечем заметить.
     */
    fun disconnect(): String = Androidbridge.disconnect()

    fun forceSwitch() = Androidbridge.forceSwitch()

    // ─── VPN (Э-4) ────────────────────────────────────────────────────────────

    /**
     * B-A13. fd — дескриптор от VpnService.Builder.establish() (владение переходит
     * Go-слою), mtu — то же значение, что передано в Builder.setMtu(). ProtectCallback
     * обязан быть установлен через setProtectCallback ДО этого вызова.
     *
     * gomobile отображает Go int в Java long (см. комментарий у activeNodeLatency) —
     * здесь это же отображение работает в обратную сторону, на вход.
     *
     * @return пустая строка при успехе, иначе текст ошибки.
     */
    fun startTun(fd: Int, mtu: Int): String = Androidbridge.startTun(fd.toLong(), mtu.toLong())

    /**
     * Находка Ш-6 (docs/TZ_ANDROID_E4_v1.1.md §3.6): startTun уходит в случайный подбор
     * узла из всего пула — вручную добавленный/заведомо рабочий узел имеет около 1% шанса
     * попасть в выборку за одну попытку. startTunToNode закрепляет и подключается к
     * КОНКРЕТНОЙ ссылке напрямую (Engine.PinNode/ConnectByID), минуя случайный подбор.
     *
     * @return пустая строка при успехе, иначе текст ошибки.
     */
    fun startTunToNode(fd: Int, mtu: Int, link: String): String =
        Androidbridge.startTunToNode(fd.toLong(), mtu.toLong(), link)

    /** TUN + подключение к ПАРТНЁРУ «Вход-Выход» (узел помечается IsChainPartner) — тот же
     * путь службы, что startTunToNode (живая находка 2026-09-28: кнопка партнёра шла мимо
     * службы и всегда поднимала «прокси», даже при включённом режиме VPN). */
    fun startTunToChainPartner(fd: Int, mtu: Int, link: String): String =
        Androidbridge.startTunToChainPartner(fd.toLong(), mtu.toLong(), link)

    /** Симметрия startTun — обратимая остановка (см. disconnect). */
    fun stopTun(): String = Androidbridge.stopTun()

    /** ТЗ v1.3 F6/КТ-14: VPN-режим к узлу из пула по ID (без ссылки), закрепление не меняется. */
    fun startTunToNodeId(fd: Int, mtu: Int, nodeId: String): String =
        Androidbridge.startTunToNodeID(fd.toLong(), mtu.toLong(), nodeId)

    /**
     * B-A02. handler вызывается Go-слоем на каждый исходящий сокет sing-box;
     * должен привести к VpnService.protect(fd) и вернуть true при успехе.
     */
    fun setProtectCallback(handler: (Int) -> Boolean) {
        Androidbridge.setProtectCallback(object : ProtectCallback {
            override fun protect(fd: Long): Boolean = handler(fd.toInt())
        })
    }

    /**
     * Задача #11, вариант 2 (2026-08-17): «зомби»-трафик в брошенный узел после
     * автопереключения — обход через пересоздание системного TUN-интерфейса на КАЖДОМ
     * Reload, а не патч самого механизма (см. androidbridge.TunFdCallback,
     * singbox.TunReloader). handler обязан вызвать buildVpnInterface() заново (тот же
     * код, что и первый запуск) и вернуть detachFd() от НОВОГО интерфейса; <= 0 — отказ
     * (например, VpnService-разрешение отозвано между переключениями).
     */
    fun setTunFdCallback(handler: () -> Int) {
        Androidbridge.setTunFdCallback(object : TunFdCallback {
            override fun requestFd(): Long = handler().toLong()
        })
    }

    // ─── Состояние ────────────────────────────────────────────────────────────

    fun isConnected(): Boolean = Androidbridge.isConnected()

    // true только после post-connect health check — см. Androidbridge.IsVerified (Go) и
    // APFVpnService.awaitVerifiedConnection.
    fun isVerified(): Boolean = Androidbridge.isVerified()

    /**
     * Общий контракт статуса канала (2026-09-06): одно из [VERIFY_IDLE], [VERIFY_CHECKING],
     * [VERIFY_VERIFIED], [VERIFY_FAILED]. Тот же смысл, что у поля `verify_state` в
     * [stateJson], но без разбора JSON.
     *
     * До этого экран определял «канал не подтверждён» разбором ПОДСТРОКИ русского текста
     * сообщения службы (`message.contains("не подтверждён")`) — любая переформулировка молча
     * ломала статус, и пользователь видел зелёное «Подключено» на канале, через который не
     * открывался ни один сайт.
     *
     * Читается из уже существующего getStateJSON, а не из отдельной функции моста, СОЗНАТЕЛЬНО:
     * поле в JSON, которого ещё нет, деградирует до фолбэка [normalizeVerifyState], а
     * отсутствующий метод в старом apf.aar — это NoSuchMethodError/несобирающийся Kotlin.
     * Одноимённая функция в мосте (Androidbridge.getVerifyState) тоже есть — для тех, кто
     * гарантированно собран из одной ревизии.
     *
     * Мост гарантирует непустой ответ даже пока движок поле не заполняет (см.
     * androidbridge.effectiveVerifyState); фолбэк ниже — вторая линия на случай старого .aar.
     */
    fun verifyState(): String = try {
        val js = org.json.JSONObject(Androidbridge.getStateJSON())
        normalizeVerifyState(
            js.optString("verify_state", ""),
            js.optBoolean("connected", false),
            js.optBoolean("verified", false)
        )
    } catch (e: Throwable) {
        normalizeVerifyState("", Androidbridge.isConnected(), Androidbridge.isVerified())
    }

    /**
     * Задержка активного узла по СКВОЗНОЙ HTTP-проверке, мс. 0 — такого замера не было;
     * это НЕ «ноль миллисекунд». Отличается от [activeNodeLatency], которая измеряет
     * TCP-рукопожатие до порта и проходит даже у узла, не пропускающего трафик.
     *
     * C-20 (ТЗ v1.4): подписывать эту величину словами «через туннель» можно ТОЛЬКО когда
     * [activeNodeVerifiedLatencySource] вернул [VERIFIED_VIA_TUN]. Прежний комментарий здесь
     * называл её «через туннель» безусловно — и именно эта формулировка разошлась по всем
     * трём интерфейсам, хотя замер почти всегда идёт через локальный SOCKS5.
     */
    fun activeNodeVerifiedLatency(): Int = try {
        org.json.JSONObject(Androidbridge.getStateJSON()).optInt("active_verified_latency_ms", 0)
    } catch (e: Throwable) {
        0
    }

    // ─── Приложения вне VPN ──────────────────────────────────────────────────
    // Общий пользовательский механизм (не под конкретный сервис): пакеты из этого списка
    // исключаются из туннеля на уровне ОС, см. APFVpnService.applyDisallowedApps.

    /** JSON-массив пакетов, исключённых из VPN. */
    fun disallowedAppsJson(): String = Androidbridge.getDisallowedAppsJSON()

    /** Заменяет список исключённых пакетов. Возвращает "" при успехе. */
    fun setDisallowedApps(packages: List<String>): String {
        val arr = org.json.JSONArray()
        packages.forEach { arr.put(it) }
        return Androidbridge.setDisallowedAppsJSON(arr.toString())
    }

    fun stateJson(): String = Androidbridge.getStateJSON()

    fun statsJson(): String = Androidbridge.getStatsJSON()

    fun nodesJson(): String = Androidbridge.getNodesJSON()

    fun activeNodeName(): String = Androidbridge.getActiveNodeName()

    // gomobile отображает Go int в Java long (Go int 64-битный), поэтому здесь toInt().
    // Проверено по сгенерированному apf.aar: getActiveNodeLatency() и getSOCKSPort()
    // объявлены как native long.
    fun activeNodeLatency(): Int = Androidbridge.getActiveNodeLatency().toInt()

    fun socksPort(): Int = Androidbridge.getSOCKSPort().toInt()

    fun diagnosticsJson(): String = Androidbridge.getDiagnosticsJSON()

    // ─── ТЗ v1.4: честное состояние (C-13, C-15, C-18, C-20, C-21) ────────────
    //
    // Все пять функций добавлены в мост лотом L1b-ENG2 (bridge.go, «новое в W1b»).
    // Прежние bool-геттеры сохранены ради совместимости старых сборок, но для
    // ИНИЦИАЛИЗАЦИИ экрана не годятся: без движка они отвечают false, а не «не знаю».
    //
    // Каждая обёрнута в try/catch по той же причине, что и [verifyState]: если .aar
    // собран из более старой ревизии моста, отсутствующий метод — это NoSuchMethodError
    // в рантайме, а не ошибка сборки Kotlin. Честный фолбэк («не знаю» / пусто) лучше
    // падения экрана.

    /**
     * C-13: трёхзначное состояние одного тумблера — [TOGGLE_ON] | [TOGGLE_OFF] |
     * [TOGGLE_UNKNOWN]. Имя — одна из констант TOGGLE_* выше.
     */
    fun toggleState(name: String): String = try {
        Androidbridge.getToggleState(name)
    } catch (e: Throwable) {
        TOGGLE_UNKNOWN
    }

    /**
     * C-13: сводка тумблеров защиты одним чтением.
     * `{"known":bool,"source":"engine"|"config","ipv6_block":bool,"webrtc_block":bool,
     *   "cyclic_search":bool,"node_auto_switch":bool,"sticky_policy":"sticky|free|timed"}`.
     *
     * `known=false` + `source="config"` означает «ядро не запущено»: положение верное
     * (взято из config.json), но живой движок его ещё не подтверждал — UI обязан показать
     * тумблер В ЭТОМ положении С ПОМЕТКОЙ, а не «выключено» (живой FAIL B2).
     */
    fun protectionStateJson(): String = try {
        Androidbridge.getProtectionStateJSON()
    } catch (e: Throwable) {
        """{"known":false,"source":"config"}"""
    }

    /**
     * C-20: чем получен замер задержки активного узла — [VERIFIED_VIA_TUN] |
     * [VERIFIED_VIA_SOCKS] | "" (замера не было). Надпись «через туннель» допустима
     * ТОЛЬКО при [VERIFIED_VIA_TUN].
     */
    fun activeNodeVerifiedLatencySource(): String = try {
        Androidbridge.getActiveNodeVerifiedLatencySource()
    } catch (e: Throwable) {
        ""
    }

    /** C-21: ФАКТИЧЕСКАЯ страна выхода активного узла ("" — неизвестна). */
    fun activeNodeExitCountry(): String = try {
        Androidbridge.getActiveNodeExitCountry()
    } catch (e: Throwable) {
        ""
    }

    /**
     * C-18: три честных числа о пуле —
     * `{"total":N,"tcp_alive":M,"proven_traffic":K,"verify_stale":S}`.
     * «Отвечает по TCP» и «подтверждён трафиком» — РАЗНЫЕ величины (живой прогон D7:
     * живых 1480 из 5467, подтверждённых трафиком — 2).
     */
    fun poolCountsJson(): String = try {
        Androidbridge.getPoolCountsJSON()
    } catch (e: Throwable) {
        """{"total":0,"tcp_alive":0,"proven_traffic":0,"verify_stale":0}"""
    }

    /**
     * C-15: объяснение результата последнего ручного «Сменить сервер» ("" — объяснять
     * нечего). Живой прогон D3: семь нажатий подряд, узел тот же, экран молчал.
     */
    fun switchNotice(): String = try {
        Androidbridge.getSwitchNotice()
    } catch (e: Throwable) {
        ""
    }

    // ─── Узлы и настройки ─────────────────────────────────────────────────────

    fun addNode(link: String): String = Androidbridge.addNode(link)

    /**
     * §4 (docs/PLAN_2026-08-28_stubs_and_realfunc.md) — роль «Вход»: ссылка от партнёра в
     * роли «Выход». В отличие от addNode подключается сразу и помечает узел как партнёра
     * цепочки (не конкурирует с публичным пулом при автовыборе/сбое).
     * @return пустая строка при успехе, иначе причина отказа.
     */
    fun connectChainPartner(link: String): String = Androidbridge.connectChainPartner(link)

    /**
     * §5 ТЗ (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md) — экран «Мои серверы»: тап по узлу.
     * Подключается к КОНКРЕТНОМУ узлу по id (из nodesJson()) и заодно закрепляет его
     * (см. pinNode) — тот же контракт, что у engine.ConnectByID.
     * @return пустая строка при успехе, иначе причина отказа (пустой/неизвестный id).
     */
    fun connectByID(nodeId: String): String = Androidbridge.connectByID(nodeId)

    /**
     * §5 ТЗ — долгий тап/иконка в «Мои серверы»: закрепляет узел БЕЗ немедленного
     * переподключения — авто-выбор (ScanAndConnect/emergencySwitch) будет предпочитать
     * его вместо топа по Score при следующем подключении/переключении.
     */
    fun pinNode(nodeId: String): String = Androidbridge.pinNode(nodeId)

    /** Снимает закрепление узла — авто-выбор возвращается к обычному ранжированию. */
    fun unpinNode(): String = Androidbridge.unpinNode()

    // ── ТЗ v1.3 F2/F3/F4 (2026-09-05): избранное, управление узлами, обход пула ──────────────
    /** Подключиться к узлу, НЕ меняя закрепление (PIN-8). "" — успех. */
    fun connectOnce(nodeId: String): String = Androidbridge.connectOnce(nodeId)
    /** TUN + подключение к узлу пула по ID (КТ-14: через службу, а не напрямую в движок). */
    fun startTunToNodeID(fd: Int, mtu: Int, nodeId: String): String =
        Androidbridge.startTunToNodeID(fd.toLong(), mtu.toLong(), nodeId)
    fun addFavorite(nodeId: String): String = Androidbridge.addFavorite(nodeId)
    fun removeFavorite(nodeId: String): String = Androidbridge.removeFavorite(nodeId)
    /** JSON-массив ID избранных узлов. */
    fun favoriteIdsJson(): String = Androidbridge.getFavoriteIDsJSON()

    // ── W3 (ТЗ v1.5 §2, TZ_v1.5_NODE_CATALOG_2026-09-14): классы избранного ──────────────────
    // Звезда пользователя (sticky, снять может только сам пользователь через removeFavorite
    // выше) и системный фаворит (добавлен сборкой каталога после пробы реального трафика,
    // снимается реконсиляцией, если проба перестала подтверждать трафик). addFavorite/
    // removeFavorite выше — ОБЩАЯ точка входа для обоих классов: звезда на системном
    // фаворите ПОВЫШАЕТ его до пользовательского, а не создаёт вторую запись.

    /** Класс избранного узла: "user" (звезда) | "system" (каталог) | "" (не в избранном). */
    fun favoriteOrigin(nodeId: String): String = Androidbridge.favoriteOrigin(nodeId)
    /** JSON-массив ID ПОЛЬЗОВАТЕЛЬСКИХ фаворитов (звезда), отдельно от системных. */
    fun userFavoriteIdsJson(): String = Androidbridge.userFavoriteIDsJSON()
    /** JSON-массив ID СИСТЕМНЫХ фаворитов (сборка каталога), отдельно от пользовательских. */
    fun systemFavoriteIdsJson(): String = Androidbridge.systemFavoriteIDsJSON()
    /** Удалить узел с надгробием — подписки его не вернут. */
    fun removeNode(nodeId: String): String = Androidbridge.removeNode(nodeId)
    fun banNode(nodeId: String, banned: Boolean): String = Androidbridge.banNode(nodeId, banned)
    /** patchJson: {"name":"…","user_note":"…"} — отсутствующее поле не трогается. */
    fun updateNode(nodeId: String, patchJson: String): String = Androidbridge.updateNodeJSON(nodeId, patchJson)
    fun resetNodeStats(nodeId: String): String = Androidbridge.resetNodeStats(nodeId)
    /** Снять надгробия; возвращает число восстановленных. */
    fun restoreRemovedNodes(): Int = Androidbridge.restoreRemovedNodes().toInt()
    /** Обход всего пула TCP-пробой без подключения. "" — запущен. */
    fun startSweep(): String = Androidbridge.startSweep()
    fun cancelSweep() = Androidbridge.cancelSweep()
    /** {"phase","done","total","alive","verified","eta_sec"}. */
    fun scanProgressJson(): String = Androidbridge.getScanProgressJSON()

    // ── ТЗ v1.5 N-1/N-3: проба реального трафика («Собрать список рабочих узлов») ────────────
    /**
     * Реальный HTTP-трафик через топ-N узлов пула (Stage 2 поверх ранжирования обхода) —
     * узел засчитывается рабочим, только когда через него прошёл настоящий трафик, а не по
     * TCP-задержке. "" — прогон запущен. Итог — значок «выход в интернет проверен»; подпись
     * «через туннель» для этой пробы недопустима (N-9): это SOCKS-проба, не системный TUN.
     */
    fun startNodeCheck(): String = Androidbridge.startNodeCheck()
    /** Отменяет текущий прогон пробы (если идёт). */
    fun cancelNodeCheck() = Androidbridge.cancelNodeCheck()
    /** {"running","phase","total","probed","verified","failed","added","target_k","started_at"}. */
    fun nodeCheckStatusJson(): String = Androidbridge.getNodeCheckStatusJSON()

    /**
     * L5-UI (ТЗ v1.4 §5): ручной харвест узлов из НАСТРОЕННЫХ источников. Обходит источники,
     * находит ссылки узлов и добавляет новые в пул НЕПРОВЕРЕННЫМИ (рабочими их делает проба
     * трафика/подключение). Ссылки-подписки движок сам не качает — отдаёт их число. "" —
     * запущено; иначе текст ошибки ("not initialized" / "харвест уже идёт").
     */
    fun harvestNow(): String = Androidbridge.harvestNow()
    /** {"running","done","error","phase","source_index","source_total","found","parsed","merged","subscription_urls","sources_processed","sources_total","stopped"}. */
    fun harvestStatusJson(): String = Androidbridge.getHarvestStatusJSON()
    /**
     * Разбор ВСТАВЛЕННОГО ПОЛЬЗОВАТЕЛЕМ текста (несколько ссылок / дамп из Telegram или страницы /
     * base64- или Clash-подписка) тем же детерминированным харвестером, что и harvestNow(), но без
     * обращения к источникам — тело приносит сам пользователь. "" — запущено; иначе текст ошибки
     * ("not initialized" / "пустой ввод" / "харвест уже идёт"). Прогресс/итог — harvestStatusJson().
     */
    fun harvestFromText(text: String): String = Androidbridge.harvestFromText(text)

    /**
     * true, если сейчас идёт любая из трёх длинных операций (обход пула, проба трафика,
     * харвест). Единая точка правды для LongOpForegroundService — вместо опроса и склейки
     * трёх разных JSON-статусов сервис раз в секунду спрашивает только это.
     */
    fun anyLongOpRunning(): Boolean = Androidbridge.anyLongOpRunning()

    /**
     * Fix B (ТЗ v1.7 PROBE-DEPTH): глубина пробы узлов трафиком (сколько верхних по рангу
     * проверять при «Собрать список рабочих узлов»). 0 = встроенный дефолт (30), иначе 10–300.
     * "" — принято, иначе текст ошибки валидации.
     */
    fun setNodeCheckTopN(n: Int): String = Androidbridge.setNodeCheckTopN(n.toLong())
    /** Текущая глубина пробы (0 = дефолт 30) — для инициализации UI. */
    fun getNodeCheckTopN(): Int = Androidbridge.getNodeCheckTopN().toInt()

    /**
     * Сообщает ядру, требуется ли Kill Switch.
     *
     * @return пустая строка, если требование принято, иначе причина отказа.
     *         Возвращаемое значение появилось вместе с исправлением D-A24: включение
     *         требования при выключенной системной защите не добавляло защиты, а
     *         отбирало связь — движок откатывал КАЖДОЕ подключение на стадии killswitch.
     */
    fun setKillSwitch(enabled: Boolean): String = Androidbridge.setKillSwitch(enabled)
    /** ТЗ v1.3 F6 (UI-A-3): сохранённое намерение пользователя — не системное состояние. */
    fun isKillSwitchEnabled(): Boolean = Androidbridge.isKillSwitchEnabled()

    fun setIPv6Block(enabled: Boolean): String = Androidbridge.setIPv6Block(enabled)

    /**
     * K2-A (свод C трек 1 п.2б): ФАКТИЧЕСКОЕ состояние защиты от IPv6-утечки у ядра.
     *
     * Экран брал начальное положение тумблера из XML-дефолта (checked=true) и никогда не
     * спрашивал ядро — выключенная пользователем защита после перезапуска активити
     * выглядела включённой. До инициализации мост отвечает false (fail-closed): «защиты
     * нет» — единственная безопасная ошибка в эту сторону.
     */
    fun isIPv6BlockEnabled(): Boolean = Androidbridge.isIPv6BlockEnabled()

    /**
     * П0.2 (docs/TZ_APF_ROADMAP_v1.2.md) — паритет с desktop GUI. Включено по умолчанию:
     * APF сам меняет узел при сбое туннеля. Выключено — при сбое остаётся на месте и
     * пишет в лог, переключение только вручную.
     */
    fun setNodeAutoSwitchEnabled(enabled: Boolean) = Androidbridge.setNodeAutoSwitchEnabled(enabled)

    fun isNodeAutoSwitchEnabled(): Boolean = Androidbridge.isNodeAutoSwitchEnabled()

    /**
     * Работает вместе с [setNodeAutoSwitchEnabled]. Включено — при исчерпании обычного
     * выбора обходит весь пул узлов по кругу вместо перехода на аварийные туннели.
     */
    fun setCyclicNodeSearch(enabled: Boolean) = Androidbridge.setCyclicNodeSearch(enabled)

    fun isCyclicNodeSearchEnabled(): Boolean = Androidbridge.isCyclicNodeSearchEnabled()

    /**
     * Режим цепочки: VPN → Proxy, два хопа вместо одного — усложняет DPI-анализ ценой
     * скорости. До этой правки на Android не было ни UI, ни моста для этой настройки.
     */
    fun setChainMode(enabled: Boolean) = Androidbridge.setChainMode(enabled)

    fun isChainModeEnabled(): Boolean = Androidbridge.isChainModeEnabled()

    /**
     * Уточняет [setChainMode]: когда цепочка уже строится, выбирать узлы РАЗНЫХ протоколов
     * для каждого звена. Без включённого режима цепочки (или автоэскалации) эффекта не даёт.
     */
    fun setMultihopEnabled(enabled: Boolean) = Androidbridge.setMultihopEnabled(enabled)

    fun isMultihopEnabled(): Boolean = Androidbridge.isMultihopEnabled()

    /** Число хопов многохоповой цепочки: 2 или 3, иное движок откатывает на 2. */
    fun setMultihopCount(n: Int) = Androidbridge.setMultihopCount(n.toLong())

    fun getMultihopCount(): Int = Androidbridge.getMultihopCount().toInt()

    fun setStickySession(policy: String) = Androidbridge.setStickySession(policy)

    /**
     * K2-A (свод C трек 1 п.2в): применённая политика Sticky Session — "sticky", "free",
     * "timed" либо пустая строка, если движок ещё не поднят.
     *
     * Единый источник истины — движок (тот же GetStickySessionStatus, что читают Web и
     * Wails), а не вторая копия выбора в SharedPreferences: две копии одной настройки
     * расходятся, и экран снова начинает показывать не то, что применено.
     */
    fun stickySessionPolicy(): String = Androidbridge.getStickySessionPolicy()

    /**
     * Сообщает ядру ФАКТИЧЕСКОЕ состояние системной защиты Android
     * («Always-on VPN» + «Блокировать соединения без VPN»).
     *
     * Приложение включить её не может — это настройка ОС. Пока метод не вызван, ядро
     * считает, что защиты нет, и откажется применять Kill Switch вместо того, чтобы
     * делать вид, будто он работает (решение D-2, fail-closed).
     */
    fun setSystemKillSwitch(active: Boolean) = Androidbridge.setSystemKillSwitch(active)

    fun isSystemKillSwitchActive(): Boolean = Androidbridge.isSystemKillSwitchActive()

    // ─── Каталог серверов (Э-UI-2) ────────────────────────────────────────────

    /** JSON-массив статусов всех провайдеров (платные/бесплатные/Tor/ручной):
     * id, name, type, enabled, trust_score, node_count, last_updated, free, region,
     * speed_class — тот же контракт, что у /api/catalog/status на десктопе. */
    fun catalogStatusJson(): String = Androidbridge.getCatalogStatusJSON()

    /** Запускает фоновое обновление узлов у включённых провайдеров; не ждёт
     * завершения (до 3 минут) — прогресс идёт через onLog, как и на десктопе. */
    fun refreshCatalog(): String = Androidbridge.refreshCatalog()

    /** @return пустая строка при успехе, иначе причина отказа (например,
     * провайдер с таким id не найден). */
    fun setCatalogProviderEnabled(id: String, enabled: Boolean): String =
        Androidbridge.setCatalogProviderEnabled(id, enabled)

    // ── W3 (ТЗ v1.5 §5): интервал пересмотра каталога ─────────────────────────────────────
    // НЕ триггер автосборки — сборка каталога только вручную (refreshCatalog/startNodeCheck
    // выше). Интервал лишь задаёт гейт давности: после этого срока проваленная проба на
    // СЛЕДУЮЩЕЙ ручной сборке вправе снять узел из системного избранного.

    /** Текущий интервал: "each_scan" (дефолт) | "daily" | "weekly" | "monthly". */
    fun catalogReviewInterval(): String = Androidbridge.catalogReviewInterval()

    /** @return пустая строка при успехе, иначе причина отказа (ядро не поднято/
     * нераспознанное значение). */
    fun setCatalogReviewInterval(v: String): String = Androidbridge.setCatalogReviewInterval(v)

    // [TZ_TAILS_HARDENING_2026-08-31.md кластер C] раньше на Android не было ни этих трёх
    // обёрток, ни экрана — вся бизнес-логика уже была на Go-стороне (Engine.AddPaidProvider и
    // соседи, реализованы для Windows в рамках roadmap v1.2, P2.1), но добавить платного
    // провайдера с телефона было физически нечем.

    /** @return JSON-массив сохранённых PaidProviderEntry (id/name/type/url/username/password/
     * token/subscription_url/enabled/insecure_tls) — для списка на экране «Платные провайдеры». */
    fun paidProvidersJson(): String = Androidbridge.getPaidProvidersJSON()

    /** entryJson — сериализованный PaidProviderEntry (id/name/type/url/username/password/
     * token/subscription_url/enabled/insecure_tls — тот же набор полей, что в Windows-панели
     * «Источники»). @return пустая строка при успехе, иначе причина отказа. */
    fun addPaidProvider(entryJson: String): String = Androidbridge.addPaidProvider(entryJson)

    /** @return пустая строка при успехе, иначе причина отказа (провайдер не найден). */
    fun removePaidProvider(id: String): String = Androidbridge.removePaidProvider(id)

    /** Пробное подключение БЕЗ сохранения (кнопка «Проверить» перед «Добавить», до 20с).
     * @return JSON {"count":N,"error":""} — число узлов от провайдера, или
     * {"count":0,"error":"..."} при отказе. */
    fun testPaidProvider(entryJson: String): String = Androidbridge.testPaidProvider(entryJson)

    // ─── Блокировка рекламы (Э-UI-3) ──────────────────────────────────────────

    /** JSON: profile, total_domains, allowlist_size, last_updated, sources_loaded,
     * sources_failed, allowlist (массив доменов) — тот же контракт, что у
     * /api/adblock/status на десктопе. */
    fun adBlockStatusJson(): String = Androidbridge.getAdBlockStatusJSON()

    /** profile: "disabled", "light", "standard", "strict". Загрузка блок-листов
     * идёт в фоне — не ждёт завершения. @return "" при успехе, иначе причина отказа. */
    fun setAdBlockProfile(profile: String): String = Androidbridge.setAdBlockProfile(profile)

    fun adBlockToggleAllowlist(domain: String, add: Boolean) =
        Androidbridge.adBlockToggleAllowlist(domain, add)

    // ─── Приватность: DNS-leak/WebRTC (Э-UI-4) ────────────────────────────────

    /** JSON: ipv6_guard_enabled, webrtc_guard_enabled, webrtc_status,
     * crypto_enabled, browser_instructions, firefox_user_js — тот же контракт,
     * что у /api/leakguard/status на десктопе. */
    fun leakGuardStatusJson(): String = Androidbridge.getLeakGuardStatusJSON()

    /** БЛОКИРУЕТ вызывающий поток на ~8-15с (реальный DNS-тест) — вызывать
     * только вне главного потока (см. showLeakGuardDialog в MainActivity.kt).
     * @return JSON результата или {"error":...,"leaked":false}. */
    fun runDnsLeakTestJson(): String = Androidbridge.runDNSLeakTestJSON()

    fun setWebRTCBlock(enabled: Boolean): String = Androidbridge.setWebRTCBlock(enabled)

    // ─── Анти-DPI/скрытность (Э-UI-5) ──────────────────────────────────────────

    /** JSON: canary (последний результат или null), padding_enabled,
     * padding_config, multihop_enabled, cdn_status, shadowtls_status — тот же
     * контракт, что у /api/dpi/status на десктопе. */
    fun dpiStatusJson(): String = Androidbridge.getDPIStatusJSON()

    /** БЛОКИРУЕТ вызывающий поток на ~15-25с (реальная проверка) — вызывать
     * только вне главного потока. @return JSON результата или {"error":...}. */
    fun runCanaryTestJson(): String = Androidbridge.runCanaryTestJSON()

    /**
     * K2-A (свод C трек 1 п.9): из UI больше НЕ вызывается — тумблеры маскировки размера
     * пакетов сняты с экрана «Анти-DPI», потому что sing-box без патча вендорного кода
     * padding не выполняет (движок отдаёт padding_enabled=false). Обёртка оставлена: она
     * ничего не стоит, а мост эту функцию по-прежнему экспортирует — удалять её здесь
     * значило бы прятать расхождение между слоями, а не устранять его.
     */
    fun setTrafficPadding(enabled: Boolean, aggressive: Boolean) =
        Androidbridge.setTrafficPadding(enabled, aggressive)

    fun setShadowTLSConfig(enabled: Boolean, password: String, sni: String, server: String, serverAddr: String) =
        Androidbridge.setShadowTLSConfig(enabled, password, sni, server, serverAddr)

    /** БЛОКИРУЕТ вызывающий поток (до 15с) — та же оговорка, что у
     * runCanaryTestJson. @return {"status":"ok","sni":"..."} или {"error":...}. */
    fun autoSelectShadowTLSSNIJson(): String = Androidbridge.autoSelectShadowTLSSNIJSON()

    fun setCDNConfig(workerDomain: String, backendHost: String, backendPort: Int) =
        Androidbridge.setCDNConfig(workerDomain, backendHost, backendPort.toLong())

    // ─── Анти-блокировка/residential IP (Э-UI-6) ──────────────────────────────

    /** JSON: enabled, residential_only, auto_switch, cache_size, current_ip_info,
     * pool_stats, bypass_rules — тот же контракт, что у /api/antiblock/status. */
    fun antiBlockStatusJson(): String = Androidbridge.getAntiBlockStatusJSON()

    /** БЛОКИРУЕТ вызывающий поток (до 10с) — вызывать только вне главного потока.
     * @return JSON с данными об IP активного узла или {"error":...}. */
    fun checkCurrentIPJson(): String = Androidbridge.checkCurrentIPJSON()

    fun setAntiBlockConfig(enabled: Boolean, residentialOnly: Boolean, autoSwitch: Boolean, apiKey: String) =
        Androidbridge.setAntiBlockConfig(enabled, residentialOnly, autoSwitch, apiKey)

    /** JSON-массив bypass-правил (встроенных и пользовательских). */
    fun bypassRulesJson(): String = Androidbridge.getBypassRulesJSON()

    fun setBypassRule(id: String, enabled: Boolean): String = Androidbridge.setBypassRule(id, enabled)

    fun addBypassDomain(domain: String, name: String, residential: Boolean, directRoute: Boolean): String =
        Androidbridge.addBypassDomain(domain, name, residential, directRoute)

    fun updateBypassDomain(
        id: String, domain: String, name: String, residential: Boolean, directRoute: Boolean
    ): String = Androidbridge.updateBypassDomain(id, domain, name, residential, directRoute)

    fun removeBypassDomain(id: String): String = Androidbridge.removeBypassDomain(id)

    // ─── Аварийная очистка + шифрование (Э-UI-7) ──────────────────────────────

    /** Пустой пароль выключает шифрование nodes_cache.json. */
    fun setMasterPassword(password: String) = Androidbridge.setMasterPassword(password)

    /** НЕОБРАТИМО стирает данные APF. confirm ДОЛЖЕН быть ровно "WIPE" — мост сам
     * это проверяет (см. Androidbridge.EmergencyWipeJSON), это не только UI-гейт.
     * @return JSON результата или {"error":...}. */
    fun emergencyWipeJson(wipeAll: Boolean, confirm: String): String =
        Androidbridge.emergencyWipeJSON(wipeAll, confirm)

    // ─── Обратные вызовы ──────────────────────────────────────────────────────

    fun onLog(handler: (String) -> Unit) {
        Androidbridge.setLogCallback(object : LogCallback {
            override fun onLog(message: String) = handler(message)
        })
    }

    fun onStateChanged(handler: (String) -> Unit) {
        Androidbridge.setStateCallback(object : StateCallback {
            override fun onStateChanged(connectedJSON: String) = handler(connectedJSON)
        })
    }

    fun onLeak(handler: (String, String) -> Unit) {
        Androidbridge.setLeakCallback(object : LeakCallback {
            override fun onLeakDetected(leakType: String, details: String) =
                handler(leakType, details)
        })
    }

    // ─── Роль «Выход» (Э-Выход-2, docs/PLAN_APF_VHOD_VYHOD_v1.0.md) ────────────
    //
    // Независимый от Connect/StartTun жизненный цикл — устройство может одновременно
    // быть «Входом» (обычный клиент выше) и «Выходом» (звеном, принимающим подключения).
    // См. mobile/androidbridge/server_role.go — там же обоснование, зачем роли без
    // собственного TUN нужен ProtectCallback (route.auto_detect_interface=true в
    // BuildServerConfig).

    /** Одноразовая генерация ключа звена. Сохранить результат на стороне Kotlin
     * (например, EncryptedSharedPreferences) — повторные вызовы StartServerRole
     * передают тот же identityJson, не генерируют заново. */
    fun generateServerIdentityJson(): String = Androidbridge.generateServerIdentityJSON()

    /** host вводится пользователем вручную (Reachability.Detect — Э-Выход-4, ещё не
     * реализована). relayAddr пусто ⇒ обычная прямая ссылка (прежнее поведение); непустой
     * ⇒ relay-формат (docs/TZ_APF_RELAY_v1.0.md §3) — параметр по умолчанию пуст, чтобы
     * существующие вызовы (без relay в UI, Фаза G) не требовали правки. relayFingerprint —
     * отпечаток TLS-сертификата relay-сервера (TZ_RELAY_HARDENING_2026-08-29.md кластер B) —
     * обязателен вместе с непустым relayAddr, иначе Go-слой честно вернёт {"error":"..."}
     * (без него партнёр получил бы ссылку, по которой EntryBridge гарантированно откажет).
     * @return JSON {"link":"vless://..."} или {"error":"..."}. */
    fun buildServerLinkJson(
        identityJson: String,
        host: String,
        listenPort: Int,
        realityDest: String,
        label: String,
        relayAddr: String = "",
        relayFingerprint: String = "",
    ): String =
        Androidbridge.buildServerLinkJSON(identityJson, host, listenPort.toLong(), realityDest, label, relayAddr, relayFingerprint)

    /** handler вызывается Go-слоем на исходящий "direct" outbound роли «Выход»;
     * тот же контракт, что и setProtectCallback выше, но для НЕЗАВИСИМОГО
     * жизненного цикла — вызывать даже если клиентский TUN не поднят. */
    fun setServerProtectCallback(handler: (Int) -> Boolean) {
        Androidbridge.setServerProtectCallback(object : ProtectCallback {
            override fun protect(fd: Long): Boolean = handler(fd.toInt())
        })
    }

    /** maxClients <= 0 ⇒ платформенный дефолт (2 — телефон, docs/TZ_APF_RELAY_v1.0.md §10.1).
     * relayAddr пусто ⇒ без relay-fallback (только прямой путь) — параметры по умолчанию
     * нейтральны, чтобы существующие вызовы (без UI-полей relay/лимита, Фаза G) не требовали
     * правки. relayFingerprint — отпечаток TLS-сертификата relay-сервера
     * (TZ_RELAY_HARDENING_2026-08-29.md кластер B) — обязателен вместе с непустым relayAddr,
     * без него ExitClient откажет fail-closed (см. internal/relay/tunnel_tls.go).
     * @return пустая строка при успехе, иначе текст ошибки. Повторный вызов на уже
     * запущенной роли — горячая перезагрузка без разрыва публичного порта (см.
     * TZ_RELAY_HARDENING_2026-08-29.md кластер A), не отказ. */
    fun startServerRole(
        listenPort: Int,
        realityDest: String,
        identityJson: String,
        maxClients: Int = 0,
        relayAddr: String = "",
        relayFingerprint: String = "",
    ): String =
        Androidbridge.startServerRole(listenPort.toLong(), realityDest, identityJson, maxClients.toLong(), relayAddr, relayFingerprint)

    /** Идемпотентна: не запущенная роль — не ошибка. */
    fun stopServerRole(): String = Androidbridge.stopServerRole()

    fun isServerRoleRunning(): Boolean = Androidbridge.isServerRoleRunning()

    /** JSON {"running":bool,"listen_port":int}. */
    fun getServerRoleStatusJson(): String = Androidbridge.getServerRoleStatusJSON()

    /** JSON-массив [{"ip":"...","interface_name":"..."}] — кандидаты на Host для ссылки роли «Выход». */
    fun getLocalIpCandidatesJson(): String = Androidbridge.getLocalIPCandidatesJSON()

    /**
     * JSON {"method":int,"explanation":"...","external_host":"...","external_port":int,"has_address":bool}
     * или {"error":"..."}. UPnP-часть требует активного WifiManager.MulticastLock со стороны
     * вызывающего (см. MainActivity.kt, doDetectReachability) — иначе Android может глушить
     * входящий SSDP-мультикаст на радио и UPnP ничего не найдёт даже при рабочем роутере.
     */
    fun detectReachabilityJson(port: Int): String = Androidbridge.detectReachabilityJSON(port.toLong())
}
