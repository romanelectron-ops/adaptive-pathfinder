package com.apf.app

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import org.json.JSONArray
import org.json.JSONObject

/**
 * FlowLayout — контейнер, который НЕ помещающиеся по ширине кнопки переносит ЦЕЛИКОМ на следующую
 * строку (а не выталкивает за край экрана и не ужимает). Нужен для рядов кнопок в диалогах: раньше
 * горизонтальный LinearLayout со смесью weight/wrap_content выталкивал часть кнопок за границу
 * экрана и они стояли вразнобой. Дети измеряются в свою естественную ширину (wrap_content) и
 * раскладываются слева направо с переносом на новую строку.
 */
private class FlowLayout(context: Context) : ViewGroup(context) {
    private val hGap = 12
    private val vGap = 12

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = View.MeasureSpec.getSize(widthMeasureSpec)
        val avail = (width - paddingLeft - paddingRight).coerceAtLeast(0)
        val childWSpec = View.MeasureSpec.makeMeasureSpec(avail, View.MeasureSpec.AT_MOST)
        val childHSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        var x = 0
        var y = 0
        var rowH = 0
        for (i in 0 until childCount) {
            val c = getChildAt(i)
            if (c.visibility == View.GONE) continue
            measureChild(c, childWSpec, childHSpec)
            val cw = c.measuredWidth
            val ch = c.measuredHeight
            if (x > 0 && x + cw > avail) { x = 0; y += rowH + vGap; rowH = 0 }
            x += cw + hGap
            if (ch > rowH) rowH = ch
        }
        setMeasuredDimension(width, View.resolveSize(paddingTop + paddingBottom + y + rowH, heightMeasureSpec))
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        val avail = (r - l) - paddingLeft - paddingRight
        var x = paddingLeft
        var y = paddingTop
        var rowH = 0
        for (i in 0 until childCount) {
            val c = getChildAt(i)
            if (c.visibility == View.GONE) continue
            val cw = c.measuredWidth
            val ch = c.measuredHeight
            if (x > paddingLeft && x - paddingLeft + cw > avail) { x = paddingLeft; y += rowH + vGap; rowH = 0 }
            c.layout(x, y, x + cw, y + ch)
            x += cw + hGap
            if (ch > rowH) rowH = ch
        }
    }
}

/**
 * MainActivity — экран управления APF.
 *
 * Режим выбирается переключателем «Режим VPN» в настройках (выключен по умолчанию —
 * «Прокси», как на этапе Э-3). Включённый режим VPN запрашивает согласие системы
 * (VpnService.prepare()) ПЕРЕД отправкой ACTION_CONNECT_VPN — APFVpnService.startVpn()
 * рассчитывает, что это согласие уже получено (см. её комментарий к startVpn()), сама
 * его не запрашивает и не должна: активити — единственное место, где можно показать
 * системный диалог.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        const val TAG = "APFMain"

        /** V1.8: ключ сохранения выбранной вкладки нижней навигации при повороте. */
        const val KEY_CURRENT_TAB = "apf_current_tab"

        /** Период страховочной перерисовки экрана, мс (дефект D7). */
        const val UI_POLL_MS = 5_000L

        /**
         * K2-A (свод C трек 1 п.2а, B4 #1): настройки САМОГО ЭКРАНА, не движка.
         *
         * Режим VPN/Прокси — это намерение пользователя относительно СЛЕДУЮЩЕГО подключения,
         * и у движка для него нет постоянного поля: Engine.SetTunMode вызывается только в
         * момент реального подключения (проверено B4 §Верификатор п.3). Поэтому источник
         * истины здесь — сторона Android, и хранить его надо ровно там же, где он живёт.
         *
         * Имя файла — то же, что уже использует BootReceiver ("apf_prefs", ключ auto_start):
         * второй файл настроек на одно приложение — это будущий вопрос «а в каком из них
         * правда», причём ровно в том слое, который этим лотом и чинится.
         */
        const val UI_PREFS = "apf_prefs"

        /** true — «Режим VPN (создаёт TUN)», false — «Прокси». Дефолт false = прежнее
         * поведение первого запуска (см. комментарий у swVpnMode в разметке). */
        const val KEY_VPN_MODE = "vpn_mode_enabled"

        /**
         * C-19 (ТЗ v1.4, UI_CONTRACT §5.3 шаг 2): пользователь подтвердил, что системные
         * «Всегда включённый VPN» + «Блокировать соединения без VPN» им включены.
         *
         * Нужен, потому что APF физически не может это прочитать: `Settings.Secure` закрыт
         * от обычного приложения без `READ_SECURE_SETTINGS`, и `getString` возвращает `null`
         * БЕЗ исключения (живой прогон K8-LIVE B5: обе системные галочки включены, fail-closed
         * реально работает, а APF бессрочно показывает «Защита неполная»). Подтверждение
         * пользователя снимает шум, но НЕ даёт зелёной ветки: зелёная надпись остаётся только
         * для фактического чтения ключа — обратная ошибка («зелено» над незащищённым
         * телефоном) хуже нынешнего шума.
         *
         * Сбрасывается в false, когда APF САМ обнаружил утечку (APFVpnService.showLeakNotification).
         */
        const val KEY_KS_CHECKLIST_ACK = "ks_checklist_ack"

        /** Ниже какой длины сообщение об ошибке ещё можно показать системным toast
         * (UI_CONTRACT §6.3: длинный toast обрезается прошивкой — живой прогон K8-LIVE,
         * текст отказа SetKillSwitch в три предложения был виден не целиком). */
        const val TOAST_MAX_CHARS = 70

        /** U-3: сколько серверов показываем за один шаг в «Моих серверах». */
        const val MY_SERVERS_PAGE = 30
    }

    private var vpnService: APFVpnService? = null
    private var serviceBound = false

    /** Роль «Выход» (Э-Выход-2) — identity живёт на время сеанса активити, не
     * персистится (эксперимент: см. showServerRoleDialog). Пусто ⇒ ещё не
     * сгенерирована в этом запуске приложения. */
    private var serverRoleIdentityJson: String = ""

    /**
     * Разрешение на уведомления (дефект D-A19).
     *
     * С Android 13 POST_NOTIFICATIONS по умолчанию НЕ выдано, и одного объявления в
     * манифесте мало. Без него служба переднего плана запускается, но её уведомление
     * не показывается — а это единственный канал, по которому пользователь видит
     * состояние подключения, получает предупреждение об утечке и может нажать
     * «Отключить», не открывая приложение. На стенде это ещё и потеря наблюдаемости:
     * сигнал OnLeakDetected просто пропадал бы.
     */
    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (!granted) {
                toast(getString(R.string.t_notifications_denied))
            }
        }

    /**
     * Согласие системы на создание TUN (VpnService.prepare()). Показывается только когда
     * prepare() вернул non-null intent — то есть согласия ещё нет или его отозвали.
     * При отказе пользователя (RESULT_CANCELED) режим остаётся отключённым — движок
     * так и не узнаёт о попытке, ACTION_CONNECT_VPN не отправляется вовсе.
     */
    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startVpnAfterConsent()
                toast(getString(R.string.t_vpn_starting))
            } else {
                // Отказ в согласии — отложенная цель подключения больше не актуальна. Без
                // сброса следующее обычное «Подключить» (startVpnAfterConsent) подхватило бы
                // старую ссылку и флаг партнёра.
                pendingVpnNodeLink = null
                pendingVpnNodeId = null
                pendingVpnChainPartner = false
                toast(getString(R.string.t_vpn_consent_denied))
            }
        }

    /** Ссылка, для которой запрошено согласие VpnService (см. vpnConsent) — поле
     * etNodeLink к моменту возврата из системного диалога уже может быть очищено
     * пользователем, поэтому значение снимается ДО запроса согласия, не после. */
    private var pendingVpnNodeLink: String? = null
    /** pendingVpnNodeLink — ссылка партнёра «Вход-Выход» (см. onConnectChainPartnerClick). */
    private var pendingVpnChainPartner: Boolean = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            vpnService = (binder as? APFVpnService.LocalBinder)?.getService()
            serviceBound = true
            updateUI()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            vpnService = null
            serviceBound = false
        }
    }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != APFVpnService.BROADCAST_STATE) return
            val state = intent.getStringExtra(APFVpnService.EXTRA_STATE) ?: "IDLE"
            val node = intent.getStringExtra(APFVpnService.EXTRA_NODE_NAME) ?: ""
            val latency = intent.getIntExtra(APFVpnService.EXTRA_LATENCY, 0)
            val message = intent.getStringExtra(APFVpnService.EXTRA_MESSAGE) ?: ""
            // Дефект D5: раньше бродкаст не нёс признака подтверждения канала вовсе, и этот
            // обработчик перерисовывал экран данными, в которых его просто не было —
            // состояние приходилось «додумывать» разбором русского текста сообщения (D4).
            val verifyState = normalizeVerifyState(
                intent.getStringExtra(APFVpnService.EXTRA_VERIFY_STATE) ?: "",
                intent.getBooleanExtra(APFVpnService.EXTRA_SESSION_ACTIVE, false),
                intent.getBooleanExtra(APFVpnService.EXTRA_CONNECTED, false)
            )
            val verifiedLatency = intent.getIntExtra(APFVpnService.EXTRA_VERIFIED_LATENCY, 0)
            runOnUiThread { renderState(state, node, latency, message, verifyState, verifiedLatency) }
        }
    }

    // ─── Периодическая переоценка состояния (дефект D7) ───────────────────────
    //
    // Экран перерисовывался ТОЛЬКО по бродкасту и в onResume. Любое залипание — пропущенный
    // бродкаст, служба, перезапущенная без активити, состояние, изменившееся тихо внутри
    // ядра — держалось сколь угодно долго: пользователь смотрел на «Подключено» ровно до
    // тех пор, пока сам что-нибудь не нажимал. Служба теперь бросает событие на КАЖДУЮ смену
    // verify_state (см. startStatusMonitor), но экран не должен зависеть от доставки одного
    // события: опрос раз в 5 с — дешёвая страховка (короткие чтения уже поднятого ядра).
    private val uiHandler = Handler(Looper.getMainLooper())
    private val uiPoller = object : Runnable {
        override fun run() {
            updateUI()
            uiHandler.postDelayed(this, UI_POLL_MS)
        }
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvNodeName: TextView
    private lateinit var tvLatency: TextView
    private lateinit var tvDisallowedAppsIndicator: TextView
    private lateinit var tvStats: TextView
    private lateinit var etNodeLink: EditText
    private lateinit var btnAddNode: Button
    private lateinit var btnConnectChainPartner: Button
    private lateinit var progressBar: ProgressBar

    /** C-21: фактическая страна выхода активного узла рядом с меткой каталога. */
    private lateinit var tvExitCountry: TextView

    /** U-17 (C-4): «узлы не сохранены: <причина>» — постоянная строка, пока движок
     * сообщает непустой `last_persist_error`, а не одноразовый toast. */
    private lateinit var tvPersistWarn: TextView

    /** C-15/D3: честное объяснение результата последнего «⇄ Сменить сервер». */
    private lateinit var tvSwitchNotice: TextView

    // CompoundButton, а не Switch: разметка может использовать SwitchMaterial,
    // который наследуется от CompoundButton, но НЕ от Switch — приведение типа
    // упало бы уже на findViewById.
    private lateinit var swKillSwitch: CompoundButton
    private lateinit var swIpv6: CompoundButton
    private lateinit var swVpnMode: CompoundButton
    private lateinit var swNodeAutoSwitch: CompoundButton
    private lateinit var swCyclicSearch: CompoundButton

    /** Найдено полным QA 2026-09-22: на Android не было ни UI, ни моста для режима цепочки/
     * многохоповой цепочки — есть в config.json и в движке, но нельзя включить иначе как
     * правкой JSON руками. rowMultihopCount скрыт, пока swMultihop выключен (как на Web). */
    private lateinit var swChainMode: CompoundButton
    private lateinit var swMultihop: CompoundButton
    private lateinit var rowMultihopCount: View
    private lateinit var spMultihopCount: Spinner

    /** LOT-K1: подсказка под Kill Switch — текст и цвет зависят от того, включена ли
     * системная защита фактически (см. updateKillSwitchHint). */
    private lateinit var tvKillSwitchHint: TextView
    private lateinit var btnOpenVpnSettings: Button

    /** C-19 шаг 2: «Я включил, скрыть» — видна только в нейтральной ветке (ключ
     * `always_on_vpn_app` прочитать не удалось) и пока подтверждения ещё нет. */
    private lateinit var btnKillSwitchAck: Button

    /** K2-A (E2 #2): та же информация, но у строки состояния — видна без прокрутки и
     * только когда защита неполная (см. updateKillSwitchHint). */
    private lateinit var tvKillSwitchStatusWarn: TextView

    /** C-13: серая пометка «ядро не запущено» под тумблерами защиты. НЕ оранжевая и не
     * красная: это не тревога, а честный факт «положение взято из сохранённых настроек». */
    private lateinit var tvProtectionUnknownHint: TextView

    private lateinit var spStickySession: Spinner
    private lateinit var btnForceSwitch: Button
    private lateinit var btnCatalog: Button
    private lateinit var btnMyServers: Button
    private lateinit var btnAdBlock: Button
    private lateinit var btnPrivacy: Button
    private lateinit var btnDpi: Button
    private lateinit var btnAntiBlock: Button
    private lateinit var btnEmergency: Button
    private lateinit var btnDiagnostics: Button

    /** U-1: «Приложения вне VPN» — единственный рабочий способ пустить банк/госуслуги мимо
     * туннеля — жил на четвёртом уровне (Главный → Анти-блокировка → низ диалога). Теперь
     * кнопка стоит в блоке защиты, рядом с Kill Switch; сам диалог не изменился. */
    private lateinit var btnDisallowedApps: Button

    /** U-18: отдельное действие для вставленной ссылки. «Подключить» больше не меняет смысл
     * от того, пусто поле или нет (E2 #16) — эта кнопка появляется, когда поле непусто. */
    private lateinit var btnAddAndConnect: Button

    // ─── Жизненный цикл ───────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        initViews()
        setupBottomNav(savedInstanceState)
        ensureNotificationPermission()
        bindVpnService()
    }

    // ─── V1.8: нижняя навигация (Главная · Защита · Узлы · Ещё) ────────────────
    // Кастомная панель, а не Material BottomNavigationView: 4 страницы-ScrollView в navHost
    // показываются/прячутся, активная вкладка подсвечивается через isSelected (цвет иконки и
    // подписи задаёт color/nav_tab_tint по state_selected + duplicateParentState). Разметка
    // распределена по 4 страницам, но ВСЕ прежние id остались в дереве — initViews()/renderState
    // находят их findViewById независимо от того, на какой странице они лежат и видима ли она.
    private val navPageIds = intArrayOf(R.id.pageHome, R.id.pageProtect, R.id.pageNodes, R.id.pageMore)
    private val navTabIds = intArrayOf(R.id.tabHome, R.id.tabProtect, R.id.tabNodes, R.id.tabMore)
    private var currentTab = 0

    private fun setupBottomNav(savedInstanceState: Bundle?) {
        for (i in navTabIds.indices) {
            findViewById<View>(navTabIds[i]).setOnClickListener { showTab(i) }
        }
        // Статус-чипы «Главной» — тап открывает вкладку с соответствующим тумблером
        // (VPN живёт на «Главной», Kill Switch и IPv6 — на «Защите»).
        findViewById<View>(R.id.chipVpn).setOnClickListener { showTab(0) }
        findViewById<View>(R.id.chipKs).setOnClickListener { showTab(1) }
        findViewById<View>(R.id.chipIpv6).setOnClickListener { showTab(1) }
        showTab(savedInstanceState?.getInt(KEY_CURRENT_TAB, 0) ?: 0)
    }

    private fun showTab(index: Int) {
        val idx = index.coerceIn(0, navPageIds.size - 1)
        currentTab = idx
        for (i in navPageIds.indices) {
            findViewById<View>(navPageIds[i]).visibility = if (i == idx) View.VISIBLE else View.GONE
            findViewById<View>(navTabIds[i]).isSelected = (i == idx)
        }
        // Чипы на «Главной» обновляем при каждом её показе — переключение вкладок не
        // вызывает onResume, а состояние тумблеров могло измениться на «Защите».
        updateStatusChips()
    }

    // V1.8 эргономика: статус-чипы-зеркала состояния защиты. Читают положение тумблеров
    // напрямую (мгновенно, без обращения к мосту): включено — зелёный, выключено —
    // приглушённый. Живут на «Главной», обновляются из showTab/updateProtectionToggles и
    // лямбды переключателя VPN.
    private fun updateStatusChips() {
        val on = 0xFF3FB950.toInt()
        val off = 0xFF8B949E.toInt()
        findViewById<TextView>(R.id.chipVpn)?.setTextColor(if (swVpnMode.isChecked) on else off)
        findViewById<TextView>(R.id.chipKs)?.setTextColor(if (swKillSwitch.isChecked) on else off)
        findViewById<TextView>(R.id.chipIpv6)?.setTextColor(if (swIpv6.isChecked) on else off)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(KEY_CURRENT_TAB, currentTab)
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(APFVpnService.BROADCAST_STATE)
        // Трёхаргументная перегрузка появилась в API 33; minSdk у нас 26 (дефект D-A10).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(stateReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(stateReceiver, filter)
        }
    }

    override fun onResume() {
        super.onResume()
        // Пользователь мог уйти в настройки ОС и включить «Блокировать соединения без VPN».
        // Ядро обязано узнать об этом, иначе продолжит считать, что защиты нет.
        vpnService?.refreshSystemKillSwitch()
        // LOT-K1: и экран обязан узнать о том же — иначе пользователь возвращается из
        // системных настроек, где он только что всё включил, к прежней красной надписи
        // «нужна ещё системная настройка» и не понимает, засчиталось ли действие.
        updateKillSwitchHint()
        // C-13 (FAIL B2): положение тумблеров защиты перечитывается при каждом возврате на
        // экран — движок мог подняться (первое подключение) уже после initViews, и тогда
        // «не знаю» обязано смениться на реальное значение, а пометка — исчезнуть.
        updateProtectionToggles()
        updateUI()
        // D7: пока экран виден — переоцениваем состояние сами, не полагаясь на доставку
        // единственного бродкаста. Снимается в onPause, вхолостую в фоне не крутится.
        uiHandler.removeCallbacks(uiPoller)
        uiHandler.postDelayed(uiPoller, UI_POLL_MS)
    }

    override fun onPause() {
        uiHandler.removeCallbacks(uiPoller)
        super.onPause()
    }

    override fun onStop() {
        super.onStop()
        try {
            unregisterReceiver(stateReceiver)
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "приёмник уже снят: $e")
        }
    }

    override fun onDestroy() {
        uiHandler.removeCallbacks(uiPoller)
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        super.onDestroy()
    }

    // ─── Инициализация ────────────────────────────────────────────────────────

    private fun initViews() {
        btnConnect = findViewById(R.id.btnConnect)
        tvStatus = findViewById(R.id.tvStatus)
        tvNodeName = findViewById(R.id.tvNodeName)
        tvLatency = findViewById(R.id.tvLatency)
        tvDisallowedAppsIndicator = findViewById(R.id.tvDisallowedAppsIndicator)
        tvStats = findViewById(R.id.tvStats)
        etNodeLink = findViewById(R.id.etNodeLink)
        btnAddNode = findViewById(R.id.btnAddNode)
        btnAddAndConnect = findViewById(R.id.btnAddAndConnect)
        btnConnectChainPartner = findViewById(R.id.btnConnectChainPartner)
        progressBar = findViewById(R.id.progressBar)
        tvExitCountry = findViewById(R.id.tvExitCountry)
        tvPersistWarn = findViewById(R.id.tvPersistWarn)
        tvSwitchNotice = findViewById(R.id.tvSwitchNotice)
        tvProtectionUnknownHint = findViewById(R.id.tvProtectionUnknownHint)
        btnKillSwitchAck = findViewById(R.id.btnKillSwitchAck)
        btnDisallowedApps = findViewById(R.id.btnDisallowedApps)
        swKillSwitch = findViewById(R.id.swKillSwitch)
        swIpv6 = findViewById(R.id.swIpv6Block)
        swVpnMode = findViewById(R.id.swVpnMode)
        swNodeAutoSwitch = findViewById(R.id.swNodeAutoSwitch)
        swCyclicSearch = findViewById(R.id.swCyclicSearch)
        swChainMode = findViewById(R.id.swChainMode)
        swMultihop = findViewById(R.id.swMultihop)
        rowMultihopCount = findViewById(R.id.rowMultihopCount)
        spMultihopCount = findViewById(R.id.spMultihopCount)
        tvKillSwitchHint = findViewById(R.id.tvKillSwitchHint)
        btnOpenVpnSettings = findViewById(R.id.btnOpenVpnSettings)
        tvKillSwitchStatusWarn = findViewById(R.id.tvKillSwitchStatusWarn)
        spStickySession = findViewById(R.id.spStickySession)
        btnForceSwitch = findViewById(R.id.btnForceSwitch)
        btnCatalog = findViewById(R.id.btnCatalog)
        btnMyServers = findViewById(R.id.btnMyServers)
        btnAdBlock = findViewById(R.id.btnAdBlock)
        btnPrivacy = findViewById(R.id.btnPrivacy)
        btnDpi = findViewById(R.id.btnDpi)
        btnAntiBlock = findViewById(R.id.btnAntiBlock)
        btnEmergency = findViewById(R.id.btnEmergency)
        btnDiagnostics = findViewById(R.id.btnDiagnostics)

        // Версия — из ядра, а не из разметки (дефект D-A26). В XML стоял «v1.0.7» при
        // собранной 1.1.0: номер, записанный в двух местах, расходится всегда, а на
        // приёмке экран начинает противоречить артефакту.
        findViewById<TextView>(R.id.tvVersion).text =
            getString(R.string.product_name) + " v" + ApfCore.version()

        btnConnect.setOnClickListener { onConnectClick() }
        btnAddNode.setOnClickListener { onAddNodeClick() }
        btnAddAndConnect.setOnClickListener { onAddAndConnectClick() }
        btnConnectChainPartner.setOnClickListener { onConnectChainPartnerClick() }
        findViewById<TextView>(R.id.tvChainPartnerHelp).setOnClickListener {
            showInfo(
                "«Это ссылка от партнёра Вход-Выход» — особый режим, не то же самое, что «Добавить». " +
                "Обычная кнопка «Добавить» кладёт узел в общий пул, где он участвует в автовыборе и " +
                "замене при сбое. Ссылка от партнёра в роли «Выход» подключается СРАЗУ и помечается как " +
                "звено цепочки: она не конкурирует с публичным пулом и при сбое не подменяется случайным " +
                "сервером. Вставляйте сюда только ссылку, которую вам дал партнёр в роли «Выход»."
            )
        }
        // U-18 (E2 #16): кнопка «Добавить и подключиться» существует ровно тогда, когда поле
        // ссылки непусто. Раньше та же самая ссылка МЕНЯЛА СМЫСЛ кнопки «Подключить», и
        // только в режиме VPN — поведение, о котором на экране не было ни слова.
        etNodeLink.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                btnAddAndConnect.isVisible = (s?.toString()?.trim()?.isNotEmpty() == true)
            }
        })
        btnAddAndConnect.isVisible = etNodeLink.text.toString().trim().isNotEmpty()
        btnDisallowedApps.setOnClickListener { showDisallowedAppsDialog() }
        btnKillSwitchAck.setOnClickListener { acknowledgeKillSwitchChecklist() }

        // K2-A (свод C трек 1 п.2а, B4 #1, E2 #8): режим VPN/Прокси восстанавливается из
        // SharedPreferences. Раньше тумблер не читал НИЧЕГО и после каждого холодного старта
        // активити стоял в «Прокси» — пользователь, вчера подключавшийся в режиме VPN, жал
        // «Подключить» и получал локальный SOCKS5, который без ручной настройки каждого
        // приложения не защищает ни байта, при этом экран показывал «Подключено».
        // Хранилище — именно телефонное: у движка постоянного поля для этого намерения нет
        // (SetTunMode применяется только в момент подключения), и заводить его в engine.go
        // ради UI-предпочтения значило бы сделать вторую копию истины.
        // C-13: и положение, и слушатели ВСЕХ тумблеров главного экрана ставятся одним общим
        // путём — не «каждый сам читает свой bool-геттер», а один трёхзначный опрос моста
        // (см. updateProtectionToggles); он же вызывается из onResume.
        updateProtectionToggles()

        findViewById<TextView>(R.id.ivInfoVpnMode).setOnClickListener {
            showInfo(
                "Режим VPN создаёт системный туннель (TUN) — через него идёт ВЕСЬ трафик " +
                    "телефона, включая другие приложения, а не только браузер. В режиме " +
                    "«Прокси» (переключатель выключен) APF поднимает только локальный " +
                    "SOCKS5/HTTP-прокси — приложения нужно настраивать на него отдельно, " +
                    "зато не запрашивается системное разрешение на VPN. Переключить можно " +
                    "только пока APF отключён."
            )
        }
        // LOT-K1: та же справка теперь открывается и с самой подсказки под тумблером, не
        // только с «ⓘ» — попасть по строке текста проще, чем по одному символу.
        findViewById<TextView>(R.id.ivInfoKillSwitch).setOnClickListener { showKillSwitchInfo() }
        tvKillSwitchHint.setOnClickListener { showKillSwitchInfo() }
        // K2-A: строка у статуса ведёт в ту же справку с кнопкой «Открыть настройки» —
        // предупреждение без пути к действию было бы просто тревогой.
        tvKillSwitchStatusWarn.setOnClickListener { showKillSwitchInfo() }
        btnOpenVpnSettings.setOnClickListener { openSystemVpnSettings() }
        findViewById<TextView>(R.id.ivInfoIpv6).setOnClickListener {
            showInfo(
                "Блокирует исходящий IPv6-трафик мимо туннеля. Многие VPN защищают только " +
                    "IPv4 — если у телефона есть рабочий IPv6, часть трафика может уйти в " +
                    "обход туннеля напрямую и раскрыть реальное местоположение. Включено по " +
                    "умолчанию — выключайте, только если точно знаете, что вам нужен IPv6."
            )
        }
        findViewById<TextView>(R.id.ivInfoNodeAutoSwitch).setOnClickListener {
            showInfo(
                "Если включено (по умолчанию) — APF сам меняет сервер при обнаруженном сбое " +
                    "туннеля. Если выключено — при сбое APF остаётся на текущем сервере и " +
                    "сообщает об этом в диагностике, не переключаясь сам; выбирайте сервер " +
                    "вручную в «Моих серверах». Выключайте, если хотите полностью ручной " +
                    "контроль над сменой сервера."
            )
        }
        findViewById<TextView>(R.id.ivInfoCyclicSearch).setOnClickListener {
            showInfo(
                "Работает вместе с «Автопереключение узлов» выше. Если включено — когда " +
                    "обычный подбор лучшего сервера исчерпан, APF обходит ВЕСЬ список " +
                    "серверов по кругу (второй, третий круг и т.д.), пока не найдёт рабочий, " +
                    "вместо немедленного перехода на аварийные запасные туннели. Выключено " +
                    "по умолчанию."
            )
        }
        findViewById<TextView>(R.id.ivInfoSticky).setOnClickListener {
            showInfo(
                "Определяет, как часто APF меняет сервер при автоматическом подборе. " +
                    "«Держаться узла» — минимизирует смену IP (полезно для сайтов, не " +
                    "любящих частую смену IP, например банков). «Свободно менять» — " +
                    "переключается сразу, как только находится узел лучше. «По таймеру» — " +
                    "меняет по расписанию независимо от качества связи."
            )
        }
        findViewById<TextView>(R.id.ivInfoChainMode).setOnClickListener {
            showInfo(
                "Строит двойной туннель VPN → Proxy: сначала обычный узел, а поверх него — " +
                    "ещё один прокси-узел, что усложняет DPI-анализ ценой скорости (два хопа " +
                    "вместо одного). Включайте, когда провайдер активно блокирует одиночные " +
                    "VPN-протоколы и обычное подключение не проходит. Выключайте, если обычное " +
                    "подключение и так работает — цепочка только замедляет."
            )
        }
        findViewById<TextView>(R.id.ivInfoMultihop).setOnClickListener {
            showInfo(
                "Уточняет «Режим цепочки» выше: когда цепочка всё равно строится (включена " +
                    "явно или APF сам эскалирует при глубокой блокировке), выбирать узлы " +
                    "РАЗНЫХ протоколов для каждого звена (например VLESS+Trojan вместо двух " +
                    "VLESS), а не просто два узла с максимальным счётом. Без «Режима цепочки» " +
                    "(и без автоэскалации) эффекта не даёт."
            )
        }

        // U-5 (E2 §3 #20): «Анти-DPI / Скрытность» и «Роль "Выход" (эксперимент)» — заголовки
        // разделов с голым термином и без единого объяснения. Текст подсказок — дословно из
        // UI_CONTRACT §1.3, п.1 и п.2 (общий словарь трёх интерфейсов).
        findViewById<TextView>(R.id.ivInfoDpi).setOnClickListener {
            showInfo(
                "DPI — способ провайдера распознавать VPN по виду трафика, а не только по " +
                    "адресу. Этот раздел — способы сделать трафик менее заметным для такой " +
                    "проверки."
            )
        }
        findViewById<TextView>(R.id.ivInfoServerRole).setOnClickListener {
            showInfo(
                "Этот телефон может сам стать промежуточным узлом для другого устройства " +
                    "владельца (цепочка Вход-Выход). Экспериментальная функция — включайте, " +
                    "только если настраивали цепочку сами."
            )
        }

        initStickySessionSpinner()
        initMultihopCountSpinner()
        btnForceSwitch.setOnClickListener { onForceSwitchClick() }
        btnCatalog.setOnClickListener { showCatalogDialog() }
        btnMyServers.setOnClickListener { showMyServersDialog() }
        btnAdBlock.setOnClickListener { showAdBlockDialog() }
        btnPrivacy.setOnClickListener { showPrivacyDialog() }
        btnDpi.setOnClickListener { showDpiDialog() }
        btnAntiBlock.setOnClickListener { showAntiBlockDialog() }
        btnEmergency.setOnClickListener { showEmergencyDialog() }
        btnDiagnostics.setOnClickListener { showDiagnosticsDialog() }
        findViewById<Button>(R.id.btnServerRole).setOnClickListener { showServerRoleDialog() }
        updateKillSwitchHint()
    }

    // ─── C-13: три состояния тумблеров защиты ─────────────────────────────────

    /**
     * C-13 (ТЗ v1.4, FAIL B2). Ставит положение тумблеров защиты по ОДНОМУ трёхзначному
     * опросу моста и честно сообщает, когда ядро ещё не запущено.
     *
     * Живой прогон K8-LIVE B2: пользователь выключил IPv6 Block, после `am force-stop` +
     * старта тумблер снова рисовался ВЫКЛ, а Диагностика показывала `IPv6 Block: true` и
     * `config.json` всё время `"block_ipv6_leak": true`. Причина на стороне UI была одна:
     * bool-геттеры моста при неподнятом движке возвращают `false`, и «не знаю» было
     * неотличимо от «выключено». Мост теперь отвечает объектом с признаком `known`
     * (см. ApfCore.protectionStateJson) — экран обязан различать эти два случая.
     *
     * `swVpnMode` включён в тот же путь СОЗНАТЕЛЬНО (UI_CONTRACT §3.2): не потому, что у него
     * была та же ошибка (её не было — режим хранится локально в apf_prefs и живой прогон B1
     * это подтвердил), а чтобы у всех тумблеров главного экрана был ОДИН путь чтения. Для
     * него `known` всегда true: локальные настройки читаются независимо от ядра.
     */
    private fun updateProtectionToggles() {
        val st = try {
            JSONObject(ApfCore.protectionStateJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор состояния тумблеров: $e")
            JSONObject()
        }
        val known = st.optBoolean("known", false)

        // Каждый тумблер отвечает на ТРЁХЗНАЧНЫЙ вопрос: "on" | "off" | "unknown".
        // «unknown» ⇒ ядро не поднято, и положение берётся из последнего сохранённого
        // конфига (его отдаёт та же сводка выше) — но НЕ «выключено».
        val ipv6 = toggleChecked(TOGGLE_IPV6_BLOCK, st.optBoolean("ipv6_block", true))
        val autoSwitch = toggleChecked(TOGGLE_NODE_AUTO_SWITCH, st.optBoolean("node_auto_switch", true))
        val cyclic = toggleChecked(TOGGLE_CYCLIC_SEARCH, st.optBoolean("cyclic_search", false))
        val chainMode = toggleChecked(TOGGLE_CHAIN_MODE, st.optBoolean("chain_mode", false))
        val multihop = toggleChecked(TOGGLE_MULTIHOP, st.optBoolean("multihop", false))
        // Режим VPN отвечает тем же трёхзначным контрактом ради единообразия кода
        // (UI_CONTRACT §3.2), но веткой unknown не пользуется никогда: SharedPreferences
        // читаются независимо от того, поднято ли ядро.
        val vpnMode = vpnModeToggleState() == TOGGLE_ON

        // Слушатель снимается на время программной установки положения и навешивается
        // заново: `isChecked = …` вызывает OnCheckedChangeListener так же, как палец
        // пользователя, и простая перерисовка экрана отправила бы в движок «команду»
        // выключить защиту (а для IPv6 — ещё и показала бы диалог подтверждения на пустом
        // месте). Приём и его причина — те же, что в restoreKillSwitch/restoreIpv6Switch.
        //
        // Обобщающего помощника с параметром-слушателем здесь СОЗНАТЕЛЬНО нет: значение
        // функционального типа пришлось бы передавать туда, где Java ждёт SAM-интерфейс
        // (см. комментарий у restoreIpv6Switch — на этом файл уже однажды не собирался).
        // Лямбда-литерал и ссылка на метод прямо в вызове Java-метода — проверенный сборкой
        // путь, поэтому четыре блока написаны буквально.

        // Режим VPN — локальная настройка экрана, ядро для неё не источник (K2-A, П2a):
        // known для него всегда true, веткой «не знаю» он не пользуется.
        swVpnMode.setOnCheckedChangeListener(null)
        swVpnMode.isChecked = vpnMode
        swVpnMode.setOnCheckedChangeListener { _, checked ->
            uiPrefs().edit().putBoolean(KEY_VPN_MODE, checked).apply()
            updateStatusChips()
        }

        swIpv6.setOnCheckedChangeListener(null)
        swIpv6.isChecked = ipv6
        swIpv6.setOnCheckedChangeListener(::onIpv6BlockToggled)

        swNodeAutoSwitch.setOnCheckedChangeListener(null)
        swNodeAutoSwitch.isChecked = autoSwitch
        swNodeAutoSwitch.setOnCheckedChangeListener { _, checked ->
            ApfCore.setNodeAutoSwitchEnabled(checked)
        }

        swCyclicSearch.setOnCheckedChangeListener(null)
        swCyclicSearch.isChecked = cyclic
        swCyclicSearch.setOnCheckedChangeListener { _, checked ->
            ApfCore.setCyclicNodeSearch(checked)
        }

        swChainMode.setOnCheckedChangeListener(null)
        swChainMode.isChecked = chainMode
        swChainMode.setOnCheckedChangeListener { _, checked ->
            ApfCore.setChainMode(checked)
        }

        swMultihop.setOnCheckedChangeListener(null)
        swMultihop.isChecked = multihop
        rowMultihopCount.isVisible = multihop
        swMultihop.setOnCheckedChangeListener { _, checked ->
            ApfCore.setMultihopEnabled(checked)
            rowMultihopCount.isVisible = checked
        }

        // Kill Switch — вне контракта C-13 (UI_CONTRACT §5.7): не независимая защита, а
        // индикатор системного требования. Читается прежним геттером.
        swKillSwitch.setOnCheckedChangeListener(null)
        swKillSwitch.isChecked = ApfCore.isKillSwitchEnabled()
        swKillSwitch.setOnCheckedChangeListener(::onKillSwitchToggled)

        // Пометка «ядро не запущено» — СЕРАЯ и без значка тревоги: это не ошибка и не
        // предупреждение, а честный факт. Оранжевый/красный здесь означал бы «что-то не
        // так», хотя всё в порядке — просто движок ещё не поднимался в этом запуске.
        tvProtectionUnknownHint.isVisible = !known

        updateStatusChips()
    }

    /**
     * C-13: положение одного тумблера по трёхзначному ответу моста.
     *
     * @param name имя тумблера — константа TOGGLE_* (те же строки, что в bridge.go).
     * @param fromConfig значение из последнего сохранённого конфига; используется ТОЛЬКО
     *        при ответе `unknown` (ядро не поднято). Подставлять `false` в этом случае
     *        нельзя — именно это и был живой FAIL B2.
     */
    private fun toggleChecked(name: String, fromConfig: Boolean): Boolean =
        when (ApfCore.toggleState(name)) {
            TOGGLE_ON -> true
            TOGGLE_OFF -> false
            else -> fromConfig
        }

    /**
     * C-13/UI_CONTRACT §3.2: тот же трёхзначный контракт для «Режима VPN».
     *
     * У этого тумблера источник истины — сторона Android (`apf_prefs`, фикс П2a лота K2-A,
     * подтверждён живьём B1), а не движок: у движка постоянного поля для этого намерения
     * нет вовсе (SetTunMode применяется только в момент подключения). Поэтому `unknown`
     * здесь невозможен по построению — функция существует ради ЕДИНОГО пути чтения для всех
     * тумблеров главного экрана, а не потому, что у режима была та же ошибка.
     */
    private fun vpnModeToggleState(): String =
        if (uiPrefs().getBoolean(KEY_VPN_MODE, false)) TOGGLE_ON else TOGGLE_OFF

    /**
     * LOT-K1 (живой запрос владельца 2026-09-06: «не нашёл как включить кил свитч и то что
     * нужно включать вместе с ним»).
     *
     * Текст один на два входа — «ⓘ» и подсказку под тумблером, — поэтому собран здесь, а не
     * продублирован в двух слушателях: разъехавшиеся копии одного объяснения — это ровно тот
     * случай, когда пользователь читает устаревшую половину и делает не то.
     */
    private fun showKillSwitchInfo() {
        showInfo(
            "Kill Switch блокирует весь интернет-трафик, если VPN-туннель обрывается — " +
                "защищает от утечки реального IP при разрыве соединения. На Android " +
                "реальную защиту даёт только системная настройка «Всегда включённый " +
                "VPN» + «Блокировать соединения без VPN» (Настройки → Сеть → VPN) — " +
                "без неё этот переключатель не добавляет защиты и просто откатывает " +
                "каждое подключение при отказе её применить.\n\n" +
                "Что включить в системе (обе галочки, одной мало):\n" +
                "1) «Всегда включённый VPN» — выберите в списке APF;\n" +
                "2) «Блокировать соединения без VPN» — она и есть настоящий Kill Switch.\n\n" +
                "Кнопка «Открыть настройки» ниже (и такая же кнопка на экране, под этим " +
                "переключателем) откроет нужный раздел системных настроек.",
            actionLabel = "Открыть настройки",
            action = { openSystemVpnSettings() }
        )
    }

    /**
     * LOT-K1: переход в системный список VPN одним тапом.
     *
     * До этого пользователь получал только текстовую инструкцию «Настройки → Сеть → VPN» и
     * должен был искать этот раздел сам — на разных прошивках он лежит по-разному
     * (Сеть и интернет / Подключения / Дополнительные функции), и владелец продукта его не
     * нашёл. Переход к конкретному приложению в этом списке системного API не имеет: включить
     * «Всегда включённый VPN» для APF по-прежнему придётся вручную, но найти экран — уже нет.
     *
     * Три кандидата подряд, а не один: ACTION_VPN_SETTINGS есть с API 24, но на части прошивок
     * (в том числе урезанных китайских) активити с этим фильтром отсутствует или закрыта.
     * Общий ACTION_SETTINGS последним — открыть корень настроек всё равно полезнее, чем
     * упереться в диалог с текстом; диалог остаётся на случай, когда не открылось НИЧЕГО.
     * SecurityException ловится наравне с ActivityNotFoundException: часть прошивок не бросает
     * «не найдено», а запрещает запуск экрана — для нас это тот же исход.
     */
    private fun openSystemVpnSettings() {
        val candidates = listOf(
            Intent(Settings.ACTION_VPN_SETTINGS),
            // Legacy-действие, на которое отвечают некоторые старые/кастомные прошивки.
            Intent("android.net.vpn.SETTINGS"),
            Intent(Settings.ACTION_SETTINGS)
        )
        for (intent in candidates) {
            try {
                startActivity(intent)
                return
            } catch (e: ActivityNotFoundException) {
                Log.w(TAG, "экран настроек не найден (${intent.action}): $e")
            } catch (e: SecurityException) {
                Log.w(TAG, "экран настроек запрещён (${intent.action}): $e")
            }
        }
        showInfo(
            "Не удалось открыть системные настройки VPN автоматически — откройте " +
                "Настройки → Сеть → VPN вручную, найдите там APF и включите " +
                "«Всегда включённый VPN», а затем «Блокировать соединения без VPN»."
        )
    }

    /**
     * LOT-K1: подсказка под Kill Switch показывает ФАКТ, а не только требование — включена
     * ли системная защита прямо сейчас.
     *
     * Читаются те же ключи Settings.Secure, что и в APFVpnService.publishSystemKillSwitchState
     * (там же объяснено, почему они могут быть недоступны обычному приложению). Поведение при
     * неудаче такое же — fail-closed: считаем, что защиты нет, и продолжаем требовать её
     * включить. Ошибиться в эту сторону безопасно: пользователь лишний раз откроет настройки
     * и увидит, что всё уже включено. Ошибка в обратную сторону означала бы зелёную надпись
     * над незащищённым телефоном.
     */
    private fun updateKillSwitchHint() {
        when (readSystemKillSwitch()) {
            SystemKs.ON -> {
                // Зелёная ветка — ТОЛЬКО по фактическому чтению ключа. Подтверждение
                // пользователя её не даёт (см. ветку UNKNOWN ниже): «зелено» над
                // незащищённым телефоном хуже нынешнего шума.
                tvKillSwitchHint.text = getString(R.string.ks_hint_green)
                tvKillSwitchHint.setTextColor(0xFF3FB950.toInt())
                btnKillSwitchAck.isVisible = false
                tvKillSwitchStatusWarn.isVisible = false
            }
            SystemKs.OFF -> {
                // Ключ прочитан и он действительно пуст/lockdown выключен — утверждать
                // «защита неполная» здесь честно.
                tvKillSwitchHint.text = getString(R.string.ks_hint_orange)
                tvKillSwitchHint.setTextColor(0xFFF5A623.toInt())
                btnKillSwitchAck.isVisible = false
                tvKillSwitchStatusWarn.text = getString(R.string.ks_status_warn)
                tvKillSwitchStatusWarn.setTextColor(0xFFF5A623.toInt())
                tvKillSwitchStatusWarn.isVisible = true
            }
            SystemKs.UNKNOWN -> {
                // C-19 шаг 2: прочитать нельзя ⇒ не утверждаем ничего. Чек-лист + две
                // кнопки вместо бессрочного «Защита неполная». Вид НЕЙТРАЛЬНЫЙ (серый):
                // ни зелёный (APF этого не знает), ни оранжевый (тревожить не за что).
                val acked = uiPrefs().getBoolean(KEY_KS_CHECKLIST_ACK, false)
                tvKillSwitchHint.text =
                    if (acked) getString(R.string.ks_hint_acked)
                    else getString(R.string.ks_hint_checklist)
                tvKillSwitchHint.setTextColor(0xFF8B949E.toInt())
                btnKillSwitchAck.isVisible = !acked
                tvKillSwitchStatusWarn.text = getString(R.string.ks_hint_checklist)
                tvKillSwitchStatusWarn.setTextColor(0xFF8B949E.toInt())
                tvKillSwitchStatusWarn.isVisible = !acked
            }
        }
    }

    /** C-19: результат попытки прочитать системный Kill Switch — ТРИ исхода, не два. */
    private enum class SystemKs { ON, OFF, UNKNOWN }

    /** C-19 шаг 1: «ключ недоступен» пишется в лог один раз за сеанс активити. */
    private var ksDiagLogged = false

    /**
     * C-19 шаг 1 (ТЗ v1.4, UI_CONTRACT §5.3): различить «прочитано и пусто» от «прочитать не
     * удалось» — и записать это в лог ОДИН раз за сессию.
     *
     * Почему это отдельный шаг, а не сразу правка текста. `Settings.Secure.getString` для
     * скрытого ключа `always_on_vpn_app` обычному приложению без `READ_SECURE_SETTINGS`
     * возвращает `null` БЕЗ исключения — то есть прежний `catch` (и лог в нём) не срабатывал
     * никогда, а `active` оставался false по построению условия. Живой прогон K8-LIVE B5:
     * обе системные галочки включены, fail-closed реально работает (`curl` → http=000), а APF
     * бессрочно показывает «⚠ Защита неполная». Без этой диагностики любая следующая правка —
     * гадание, а не вывод.
     *
     * `null` трактуется как UNKNOWN, а не как OFF, СОЗНАТЕЛЬНО: отличить «ключ не выставлен»
     * от «ключ не читается» изнутри приложения нельзя, а утверждать то, чего не знаешь, —
     * ровно тот класс лжи интерфейса, который чинит всё это ТЗ. Оранжевое утверждение
     * возвращается, когда APF САМ обнаружил утечку (APFVpnService сбрасывает подтверждение).
     */
    private fun readSystemKillSwitch(): SystemKs {
        // try как ВЫРАЖЕНИЕ, а не блок с присваиванием val снаружи: так у компилятора нет
        // ни одной ветки, где значение могло бы остаться неинициализированным.
        val read: Pair<String?, Int>? = try {
            Pair(
                Settings.Secure.getString(contentResolver, "always_on_vpn_app"),
                Settings.Secure.getInt(contentResolver, "always_on_vpn_lockdown", 0)
            )
        } catch (e: Throwable) {
            if (!ksDiagLogged) {
                ksDiagLogged = true
                val msg = "C-19: чтение always_on_vpn_* БРОСИЛО исключение: $e"
                Log.w(TAG, msg)
                ApfFileLogger.log("W", TAG, msg)
            }
            null
        }
        if (read == null) return SystemKs.UNKNOWN
        val app: String? = read.first
        val lockdown: Int = read.second
        if (app == null) {
            if (!ksDiagLogged) {
                ksDiagLogged = true
                val msg = "C-19: always_on_vpn_app вернул null БЕЗ исключения — ключ " +
                    "недоступен приложению (нет READ_SECURE_SETTINGS) либо не выставлен; " +
                    "различить изнутри нельзя, показываю чек-лист вместо утверждения"
                Log.i(TAG, msg)
                ApfFileLogger.log("I", TAG, msg)
            }
            return SystemKs.UNKNOWN
        }
        if (!ksDiagLogged) {
            ksDiagLogged = true
            val msg = "C-19: always_on_vpn_app ПРОЧИТАН (пусто=${app.isEmpty()}), " +
                "always_on_vpn_lockdown=$lockdown"
            Log.i(TAG, msg)
            ApfFileLogger.log("I", TAG, msg)
        }
        return if (app.isNotEmpty() && lockdown == 1) SystemKs.ON else SystemKs.OFF
    }

    /**
     * C-19 шаг 2: «Я включил, скрыть». Ответ хранится в том же `apf_prefs`, что и режим VPN
     * (П2a), и снимается только тогда, когда APF сам обнаружил утечку — не по таймеру и не
     * при каждом возврате на экран (см. APFVpnService.showLeakNotification).
     */
    private fun acknowledgeKillSwitchChecklist() {
        uiPrefs().edit().putBoolean(KEY_KS_CHECKLIST_ACK, true).apply()
        updateKillSwitchHint()
    }

    /**
     * K2-A: настройки самого экрана (см. UI_PREFS/KEY_VPN_MODE).
     *
     * Отдельный метод, а не поле: initViews вызывается из onCreate, и обращение к
     * getSharedPreferences в инициализаторе поля выполнилось бы раньше, чем у активити
     * появится контекст.
     */
    private fun uiPrefs() = getSharedPreferences(UI_PREFS, Context.MODE_PRIVATE)

    /**
     * K2-A (E2 #11, свод C трек 1 п.14): подтверждение на СНЯТИЕ защиты.
     *
     * Асимметрия, найденная консилиумом E2: включение Kill Switch в десктопном UI
     * подтверждается, а выключение — нигде и ни в одном из трёх интерфейсов; один
     * случайный тап по тумблеру молча снимал защиту, и обратной связи об этом не было
     * никакой. Включение защиты не трогаем: спрашивать «вы уверены?» на действии, которое
     * делает пользователя безопаснее, — это учить его отмахиваться от диалогов.
     *
     * onCancel обязателен: тумблер уже физически переключился пользователем, и отказ в
     * диалоге должен вернуть его на место, иначе экран снова начнёт показывать не то,
     * что применено (тот же класс дефекта, что чинят п.2а-2в).
     */
    private fun confirmDisableProtection(
        title: String,
        message: String,
        onConfirm: () -> Unit,
        onCancel: () -> Unit,
    ) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Выключить") { _, _ -> onConfirm() }
            .setNegativeButton("Отмена") { _, _ -> onCancel() }
            // Кнопка «назад» и тап мимо диалога — это тоже отказ, а не тихое согласие.
            .setOnCancelListener { onCancel() }
            .show()
    }

    /**
     * K2-A: возврат тумблера IPv6 в прежнее положение без повторного вызова слушателя.
     *
     * Общего помощника «вернуть любой тумблер» намеренно нет: слушатель приходилось бы
     * передавать значением функционального типа в место, где Java ждёт SAM-интерфейс, —
     * а в этом файле уже есть проверенный сборкой приём (onKillSwitchToggled), и он
     * повторён буквально, ссылкой на метод.
     */
    private fun restoreIpv6Switch(view: CompoundButton, checked: Boolean) {
        view.setOnCheckedChangeListener(null)
        view.isChecked = checked
        view.setOnCheckedChangeListener(::onIpv6BlockToggled)
    }

    /**
     * Э-UI-1 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.1). ApfCore.setStickySession уже
     * оборачивает Androidbridge.setStickySession, но MainActivity его не вызывал —
     * StickySessionManager на движке молча оставался на политике по умолчанию, выбор
     * пользователя нигде не показывался и не применялся.
     *
     * Значения ("sticky"/"free"/"timed") — контракт ApfCore.setStickySession
     * (см. internal/engine SetStickyPolicy), не придуманы здесь.
     */
    private val stickyPolicies = arrayOf("sticky", "free", "timed")
    private val stickyLabels = arrayOf("Держаться узла", "Свободно менять", "По таймеру")

    private fun initStickySessionSpinner() {
        spStickySession.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, stickyLabels
        )
        // K2-A (свод C трек 1 п.2в, B4 #1): показываем ПРИМЕНЁННУЮ политику, а не первую
        // строку списка. Раньше спиннер всегда стартовал на «Держаться узла», и его же
        // onItemSelected при построении списка тут же отправлял в движок "sticky" — то есть
        // каждое открытие экрана молча отменяло выбор «Свободно менять»/«По таймеру».
        // Пустая строка (движок ещё не поднят) — оставляем позицию по умолчанию и НИЧЕГО
        // не применяем: подставлять политику от лица пользователя нельзя.
        // C-13: политика берётся из той же сводки, что и остальные тумблеры защиты —
        // GetProtectionStateJSON отдаёт её из config.json, когда ядро ещё не поднято
        // (прежний stickySessionPolicy() в этом случае возвращал пустую строку, и спиннер
        // молча оставался на первой позиции списка, а не на применённой политике).
        val current = try {
            JSONObject(ApfCore.protectionStateJson()).optString("sticky_policy", "")
        } catch (e: Exception) {
            ApfCore.stickySessionPolicy()
        }
        val startIndex = stickyPolicies.indexOf(current)
        if (startIndex >= 0) spStickySession.setSelection(startIndex)
        // Первое срабатывание — это отрисовка выбранной позиции, а не выбор пользователя
        // (тот же приём и та же причина, что у спиннера профиля в showAdBlockDialog).
        var spinnerReady = false
        spStickySession.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (!spinnerReady) { spinnerReady = true; return }
                ApfCore.setStickySession(stickyPolicies[position])
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private val multihopCounts = intArrayOf(2, 3)
    private val multihopLabels = arrayOf("2 хопа", "3 хопа")

    /** Тот же приём, что и у [initStickySessionSpinner]: показываем ПРИМЕНЁННОЕ число хопов
     * и не отправляем его в движок на первой (программной) отрисовке позиции. */
    private fun initMultihopCountSpinner() {
        spMultihopCount.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, multihopLabels
        )
        val startIndex = multihopCounts.indexOf(ApfCore.getMultihopCount())
        if (startIndex >= 0) spMultihopCount.setSelection(startIndex)
        var spinnerReady = false
        spMultihopCount.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (!spinnerReady) { spinnerReady = true; return }
                ApfCore.setMultihopCount(multihopCounts[position])
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    /** Э-UI-1: ApfCore.forceSwitch уже был в мосте — кнопки, чтобы его вызвать, не было. */
    private fun onForceSwitchClick() {
        // isSessionActive(), а не isConnected(): переключать сервер нужно ИМЕННО тогда, когда
        // канал не подтверждён (D9 — isConnected() теперь означает «подтверждён», и требовать
        // подтверждения здесь значило бы запретить смену узла ровно в нужный момент).
        if (vpnService?.isSessionActive() != true) {
            // U-16 (UI_CONTRACT §1.1): единый текст отказа на всех трёх интерфейсах.
            toast(getString(R.string.t_switch_nothing))
            return
        }
        ApfCore.forceSwitch()
        toast(getString(R.string.t_switch_in_progress))
        // C-15 / живой FAIL D3: семь нажатий подряд — узел тот же, а экран молчал, потому
        // что движок в ситуации «другого рабочего узла нет» просто ничего не менял. Теперь
        // он объясняет это строкой SwitchNotice; забираем её через пару секунд (переключение
        // асинхронное) и показываем — updateUI подхватит её и на следующих циклах опроса.
        uiHandler.postDelayed({ if (!isFinishing) updateSwitchNotice() }, 3_000L)
    }

    /**
     * C-15/D3: честное объяснение результата ручного «⇄ Сменить сервер».
     *
     * Отдельная строка на экране, а не toast: toast исчезает через несколько секунд, а
     * причина «другого рабочего узла не нашлось» остаётся верной, пока пул не изменится.
     * Пусто ⇒ строка скрыта (в норме объяснять нечего).
     */
    private fun updateSwitchNotice() {
        val notice = ApfCore.switchNotice()
        tvSwitchNotice.isVisible = notice.isNotEmpty()
        if (notice.isNotEmpty()) tvSwitchNotice.text = notice
    }

    /**
     * Э-UI-2 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.2). ApfCore.catalogStatusJson/
     * refreshCatalog/setCatalogProviderEnabled уже в мосте (internal/catalog на бэкенде
     * давно работает и открыт на десктопе, эндпоинты /api/catalog/...) — экрана на
     * Android не было, Android умел добавить только одну ссылку за раз.
     *
     * Список строится программно (LinearLayout в ScrollView), а не RecyclerView с
     * адаптером: провайдеров единицы (4 бесплатных + Tor + ручной, обычно без платных
     * панелей) — отдельный адаптер был бы избыточен для этого объёма. «Обновить каталог»
     * не ждёт завершения (до 3 минут на все провайдеры сразу) — прогресс виден в общем
     * логе движка (onLog), отдельный канал не заводится.
     */

    /** Русское склонение «узел/узла/узлов» по числу (стандартное mod10/mod100 правило). */
    private fun pluralNodes(n: Int): String {
        val mod100 = n % 100
        val mod10 = n % 10
        return when {
            mod100 in 11..14 -> "узлов"
            mod10 == 1 -> "узел"
            mod10 in 2..4 -> "узла"
            else -> "узлов"
        }
    }

    private fun showCatalogDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }

        var dialogRef: AlertDialog? = null

        // Опрашивает статус каталога после "Обновить каталог" и пересобирает диалог, как
        // только снимок реально изменился — найдено QA 2026-08-18: refreshCatalog()
        // асинхронный (см. доккомментарий класса выше), и диалог, построенный ДО завершения
        // обновления, продолжал показывать старые счётчики узлов сколько угодно долго, хотя
        // бэкенд их уже обновил (подтверждено логкатом "added N new nodes"). Актуальные цифры
        // появлялись только при закрытии+повторном открытии диалога вручную. До 60 попыток по
        // 3с (~3 мин, тот же потолок, что у самого обновления) — останавливается, как только
        // catalogStatusJson() перестаёт совпадать со снимком на момент нажатия кнопки.
        fun pollCatalogRefresh(baselineJson: String, attempt: Int = 0) {
            if (attempt >= 60 || isFinishing) return
            container.postDelayed({
                if (isFinishing) return@postDelayed
                val current = ApfCore.catalogStatusJson()
                if (current != baselineJson) {
                    dialogRef?.dismiss()
                    showCatalogDialog()
                } else {
                    pollCatalogRefresh(baselineJson, attempt + 1)
                }
            }, 3000)
        }

        val baselineCatalogJson = ApfCore.catalogStatusJson()
        container.addView(Button(this).apply {
            text = "Обновить каталог"
            setOnClickListener {
                val err = ApfCore.refreshCatalog()
                if (err.isEmpty()) {
                    toast(getString(R.string.t_catalog_refreshing))
                } else {
                    showErrorMessage(getString(R.string.e_catalog_refresh, bridgeErrorText(err)))
                }
                if (err.isEmpty()) pollCatalogRefresh(baselineCatalogJson)
            }
        })

        // [TZ_TAILS_HARDENING_2026-08-31.md кластер C] раньше на Android не было ни этой
        // кнопки, ни экрана — бизнес-логика (Engine.AddPaidProvider) уже была готова для
        // Windows (roadmap v1.2, P2.1), но добавить платного провайдера с телефона было
        // физически нечем.
        container.addView(Button(this).apply {
            text = "Платные провайдеры"
            setOnClickListener { showPaidProvidersDialog() }
        })

        // ─── W3 (ТЗ v1.5 §5, TZ_v1.5_NODE_CATALOG_2026-09-14): интервал пересмотра каталога ──
        // Честно: это НЕ таймер автосборки (сборка каталога только по кнопке пользователя,
        // owner-декрет консилиума) — гейт давности для системного избранного, см. подробности
        // в infoRow ниже и doc-комментарий у Engine.CatalogReviewInterval.
        container.addView(TextView(this).apply {
            text = getString(R.string.catalog_review_interval_label)
            setPadding(0, 24, 0, 8)
        })
        container.addView(infoRow(getString(R.string.catalog_review_interval_hint)))
        val reviewIntervalValues = arrayOf("each_scan", "daily", "weekly", "monthly")
        val reviewIntervalLabels = arrayOf(
            "При каждой проверке", "Раз в день", "Раз в неделю", "Раз в месяц"
        )
        val spReviewInterval = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity, android.R.layout.simple_spinner_dropdown_item, reviewIntervalLabels
            )
        }
        val reviewStartIndex = reviewIntervalValues.indexOf(ApfCore.catalogReviewInterval())
        spReviewInterval.setSelection(if (reviewStartIndex < 0) 0 else reviewStartIndex)
        // Тот же приём, что у спиннера профиля AdBlock (showAdBlockDialog) и у
        // initStickySessionSpinner: без флага первое открытие диалога отправило бы в бридж
        // уже применённое значение, как будто это осознанный выбор пользователя.
        var reviewIntervalSpinnerReady = false
        spReviewInterval.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (!reviewIntervalSpinnerReady) { reviewIntervalSpinnerReady = true; return }
                val err = ApfCore.setCatalogReviewInterval(reviewIntervalValues[position])
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_review_interval, bridgeErrorText(err)))
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        container.addView(spReviewInterval)

        val providers = try {
            JSONArray(ApfCore.catalogStatusJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор каталога: $e")
            JSONArray()
        }
        if (providers.length() == 0) {
            container.addView(TextView(this).apply {
                text = "Список провайдеров пуст"
                setTextColor(getColor(android.R.color.darker_gray))
            })
        }
        for (i in 0 until providers.length()) {
            val p = providers.optJSONObject(i) ?: continue
            val id = p.optString("id")
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(0, 20, 0, 20)
            }
            row.addView(TextView(this).apply {
                text = "${p.optString("name", id)} (${p.optString("type")}) — " +
                    "${p.optInt("node_count")} ${pluralNodes(p.optInt("node_count"))}"
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            val sw = Switch(this)
            // Именованная переменная, а не инлайн-лямбда: при отказе бэкенда переключатель
            // обязан откатиться на прежнее значение (экран показывает состояние ядра, а не
            // намерение пользователя — тот же принцип, что у onKillSwitchToggled), а для
            // отката нужно временно снять и снова навесить ЭТОТ ЖЕ слушатель.
            lateinit var listener: CompoundButton.OnCheckedChangeListener
            listener = CompoundButton.OnCheckedChangeListener { view, checked ->
                val err = ApfCore.setCatalogProviderEnabled(id, checked)
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_catalog_provider_toggle, bridgeErrorText(err)))
                    view.setOnCheckedChangeListener(null)
                    view.isChecked = !checked
                    view.setOnCheckedChangeListener(listener)
                }
            }
            sw.isChecked = p.optBoolean("enabled")
            sw.setOnCheckedChangeListener(listener)
            row.addView(sw)
            container.addView(row)
        }

        dialogRef = AlertDialog.Builder(this)
            .setTitle("Каталог серверов")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    /**
     * [TZ_TAILS_HARDENING_2026-08-31.md кластер C] Экран «Платные провайдеры» — раньше на
     * Android не было ни этого экрана, ни моста к нему: вся бизнес-логика
     * (Engine.AddPaidProvider/RemovePaidProvider/TestPaidProvider) уже была готова для Windows
     * (roadmap v1.2, P2.1), но добавить платного провайдера (3x-ui/Marzban/Hiddify/подписка) с
     * телефона было физически нечем. Те же поля, что в Windows-панели «Источники».
     *
     * AddPaidProvider/TestPaidProvider на Go-стороне синхронно ходят в сеть (до 15-20с,
     * Engine.AddPaidProvider делает реальный p.Fetch(ctx)) — вызов ИЗ UI-потока подвесил бы
     * интерфейс на это время (и рискует NetworkOnMainThreadException); оба вызова здесь идут в
     * фоновом Thread с возвратом на UI через runOnUiThread, тот же приём, что pollCatalogRefresh
     * использует для длительного опроса выше.
     */
    private fun showPaidProvidersDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        var dialogRef: AlertDialog? = null

        fun header(text: String) {
            container.addView(TextView(this).apply {
                this.text = text
                setTextColor(getColor(android.R.color.darker_gray))
                setPadding(0, 24, 0, 8)
            })
        }

        header("Сохранённые провайдеры")
        val providers = try {
            JSONArray(ApfCore.paidProvidersJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор платных провайдеров: $e")
            JSONArray()
        }
        if (providers.length() == 0) {
            container.addView(TextView(this).apply {
                text = "Провайдеров пока нет"
                setTextColor(getColor(android.R.color.darker_gray))
            })
        }
        for (i in 0 until providers.length()) {
            val p = providers.optJSONObject(i) ?: continue
            val id = p.optString("id")
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(0, 12, 0, 12)
            }
            row.addView(TextView(this).apply {
                text = "${p.optString("name", id)} (${p.optString("type")})"
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(Button(this).apply {
                text = "Удалить"
                setOnClickListener {
                    val err = ApfCore.removePaidProvider(id)
                    if (err.isEmpty()) {
                        toast(getString(R.string.t_provider_removed))
                        dialogRef?.dismiss()
                        showPaidProvidersDialog()
                    } else {
                        showErrorMessage(getString(R.string.e_provider_remove, bridgeErrorText(err)))
                    }
                }
            })
            container.addView(row)
        }

        header("Добавить провайдера")
        val etName = EditText(this).apply { hint = "Название" }
        container.addView(etName)

        val typeLabels = listOf("3x-ui", "Marzban", "Hiddify", "Подписка (URL)")
        val typeValues = listOf("3xui", "marzban", "hiddify", "subscription")
        val spType = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity, android.R.layout.simple_spinner_dropdown_item, typeLabels
            )
        }
        container.addView(spType)

        val etUrl = EditText(this).apply { hint = "URL панели / базовый адрес" }
        container.addView(etUrl)
        val etUsername = EditText(this).apply { hint = "Логин" }
        container.addView(etUsername)
        val etPassword = EditText(this).apply {
            hint = "Пароль"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        container.addView(etPassword)
        val etToken = EditText(this).apply { hint = "Токен (если применимо)" }
        container.addView(etToken)
        val etSubUrl = EditText(this).apply { hint = "Ссылка подписки (для типа «Подписка»)" }
        container.addView(etSubUrl)

        val swInsecure = Switch(this).apply { text = "Не проверять TLS-сертификат" }
        container.addView(swInsecure)

        val tvResult = TextView(this).apply { setPadding(0, 12, 0, 12) }
        container.addView(tvResult)

        fun buildEntryJson(): String {
            val o = JSONObject()
            o.put("name", etName.text.toString())
            o.put("type", typeValues[spType.selectedItemPosition])
            o.put("url", etUrl.text.toString())
            o.put("username", etUsername.text.toString())
            o.put("password", etPassword.text.toString())
            o.put("token", etToken.text.toString())
            o.put("subscription_url", etSubUrl.text.toString())
            o.put("enabled", true)
            o.put("insecure_tls", swInsecure.isChecked)
            return o.toString()
        }

        container.addView(Button(this).apply {
            text = "Проверить подключение"
            setOnClickListener {
                tvResult.text = "Проверяю…"
                val entryJson = buildEntryJson()
                Thread {
                    val resultJson = ApfCore.testPaidProvider(entryJson)
                    runOnUiThread {
                        if (isFinishing) return@runOnUiThread
                        try {
                            val r = JSONObject(resultJson)
                            val err = r.optString("error")
                            tvResult.text = if (err.isEmpty())
                                "OK: найдено узлов — ${r.optInt("count")}"
                            else "Ошибка: $err"
                        } catch (e: Exception) {
                            tvResult.text = "Ошибка разбора ответа: $e"
                        }
                    }
                }.start()
            }
        })

        container.addView(Button(this).apply {
            text = "Добавить"
            setOnClickListener {
                if (etName.text.isBlank()) {
                    toast(getString(R.string.t_provider_need_name))
                    return@setOnClickListener
                }
                val entryJson = buildEntryJson()
                tvResult.text = "Добавляю…"
                Thread {
                    val err = ApfCore.addPaidProvider(entryJson)
                    runOnUiThread {
                        if (isFinishing) return@runOnUiThread
                        if (err.isEmpty()) {
                            toast(getString(R.string.t_provider_added))
                            dialogRef?.dismiss()
                            showPaidProvidersDialog()
                        } else {
                            tvResult.text = "Ошибка: ${bridgeErrorText(err)}"
                        }
                    }
                }.start()
            }
        })

        // U-2 (E2 #10, D1 §4): из этого диалога не было пути назад — закрытие выбрасывало на
        // главный экран, и пользователь, зашедший «Каталог → Платные провайдеры», терял место.
        // Теперь и кнопка, и системная «назад»/тап мимо возвращают в родительский каталог.
        dialogRef = AlertDialog.Builder(this)
            .setTitle("Платные провайдеры")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton(getString(R.string.btn_back_to_catalog)) { _, _ -> showCatalogDialog() }
            .setOnCancelListener { showCatalogDialog() }
            .show()
    }

    /**
     * §5 ТЗ (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md): «Мои серверы». `GetNodesJSON`→
     * `ApfCore.nodesJson()` и `PinNode`/`UnpinNode`/`ConnectByID` уже были доведены до
     * bridge.go/ApfCore.kt (2026-08-13, для этого экрана) — раньше вызывались только из
     * headless HTTP API (internal/web/server.go), с Android не было связано ничего.
     *
     * Список строится программно (тот же приём, что showCatalogDialog/showAdBlockDialog —
     * записей обычно немного, отдельный RecyclerView-адаптер избыточен). Тап по узлу —
     * ConnectByID (подключает и заодно закрепляет — engine.ConnectByID уже это делает).
     * Кнопка «Закрепить»/«Открепить» — PinNode/UnpinNode БЕЗ немедленного подключения:
     * авто-выбор будет предпочитать закреплённый узел при следующем ScanAndConnect/
     * emergencySwitch, но текущий сеанс не трогает.
     */
    private var pendingVpnNodeId: String? = null

    /**
     * ТЗ v1.3 F6/КТ-14: «Подключить» из «Моих серверов» идёт ЧЕРЕЗ СЛУЖБУ (состояние экрана,
     * уведомление и TUN — у неё), а не прямым вызовом ядра из активити. Закрепление не меняется
     * (PIN-8: тап = ConnectOnce, «Закрепить» — отдельное действие). Если сеанс уже поднят —
     * переключение внутри сеанса (ядро само пересоздаст TUN, как при «Сменить сервер»).
     */
    private fun connectToNodeViaService(id: String, name: String) {
        val service = vpnService
        // isSessionActive(): переключение внутри живого сеанса не требует, чтобы текущий
        // канал был подтверждён (D9) — чаще всего его меняют как раз из-за обратного.
        if (service != null && service.isSessionActive()) {
            val err = ApfCore.connectOnce(id)
            if (err.isNotEmpty()) {
                showErrorMessage(getString(R.string.e_connect, bridgeErrorText(err)))
            } else {
                toast(getString(R.string.t_switching_to, name))
            }
            return
        }
        if (swVpnMode.isChecked) {
            val consentIntent = VpnService.prepare(this)
            if (consentIntent != null) {
                pendingVpnNodeId = id
                vpnConsent.launch(consentIntent)
                return
            }
            startForegroundService(Intent(this, APFVpnService::class.java).apply {
                action = APFVpnService.ACTION_CONNECT_VPN_TO_NODE_ID
                putExtra(APFVpnService.EXTRA_NODE_ID, id)
            })
            toast(getString(R.string.t_vpn_starting_to, name))
        } else {
            startForegroundService(Intent(this, APFVpnService::class.java).apply {
                action = APFVpnService.ACTION_CONNECT_PROXY_TO_NODE_ID
                putExtra(APFVpnService.EXTRA_NODE_ID, id)
            })
            toast(getString(R.string.t_proxy_connecting_to, name))
        }
    }

    /** Опрос прогресса обхода пула, пока диалог открыт (ТЗ v1.3 F4 Stage 1). */
    private fun pollScanProgress(target: TextView, dialog: AlertDialog?, attempt: Int = 0) {
        if (dialog != null && !dialog.isShowing) return
        val p = try { JSONObject(ApfCore.scanProgressJson()) } catch (e: Exception) { JSONObject() }
        val phase = p.optString("phase", "idle")
        val verified = p.optInt("verified")
        val verifiedText = if (verified > 0) " · подтверждённых трафиком: $verified" else ""
        target.text = when (phase) {
            "running" -> {
                val eta = p.optInt("eta_sec")
                val etaText = if (eta > 0) " · осталось ~${if (eta >= 90) "${eta / 60} мин" else "$eta с"}" else ""
                "Обход: ${p.optInt("done")} / ${p.optInt("total")} · живых ${p.optInt("alive")}$etaText$verifiedText"
            }
            "done" -> "Обход завершён: живых ${p.optInt("alive")} из ${p.optInt("total")}$verifiedText"
            "cancelled" -> "Обход остановлен на ${p.optInt("done")} / ${p.optInt("total")} — продолжится с этого места$verifiedText"
            else -> if (verified > 0) "Подтверждённых трафиком: $verified" else ""
        }
        if (phase == "running" && attempt < 600) {
            target.postDelayed({ pollScanProgress(target, dialog, attempt + 1) }, 1000)
        } else if ((phase == "done" || phase == "cancelled") && dialog != null && dialog.isShowing) {
            // P1-1 (ТЗ v1.6): TCP-обход завершился — статусы/бейджи узлов изменились, а allNodes
            // диалога устарел (взят при открытии). Пересобираем со свежим списком. Гейт dialog != null
            // — как в pollNodeCheckStatus (стартовый вызов не рефрешит, иначе цикл reopen).
            dialog.dismiss()
            showMyServersDialog()
        }
    }

    /**
     * Опрос прогресса пробы РЕАЛЬНОГО трафика (ТЗ v1.5 N-1/N-3), пока диалог открыт.
     * Честная формулировка (N-9/C3): «выход в интернет проверен» — НИКОГДА «через туннель»,
     * эта проба идёт через локальный SOCKS проб-слота, а не системный TUN устройства.
     */
    private fun pollNodeCheckStatus(target: TextView, dialog: AlertDialog?, attempt: Int = 0) {
        if (dialog != null && !dialog.isShowing) return
        val p = try { JSONObject(ApfCore.nodeCheckStatusJson()) } catch (e: Exception) { JSONObject() }
        val phase = p.optString("phase", "")
        val probed = p.optInt("probed")
        val total = p.optInt("total")
        val verified = p.optInt("verified")
        val targetK = p.optInt("target_k")
        target.text = when (phase) {
            "probing" -> "Проверка трафика: $probed / $total · подтверждено $verified из $targetK"
            "done" -> "Проверка завершена: выход в интернет проверен у $verified из $probed"
            "cancelled" -> "Проверка остановлена на $probed / $total · подтверждено $verified"
            else -> ""
        }
        if (phase == "probing" && attempt < 600) {
            target.postDelayed({ pollNodeCheckStatus(target, dialog, attempt + 1) }, 1000)
        } else if ((phase == "done" || phase == "cancelled") && dialog != null && dialog.isShowing) {
            // P1-1 (ТЗ v1.6): проба завершилась — allNodes диалога взят при его ОТКРЫТИИ, до пробы,
            // поэтому свежеподтверждённые узлы (last_verified_via socks5) не появлялись бы как
            // проверенные и фильтр «Подтверждённые трафиком» показывал бы пусто. Пересобираем диалог
            // со свежим GetNodesJSON. Гейт dialog != null: стартовый вызов (dialog=null при открытии)
            // только ПОКАЗЫВАЕТ статус и НЕ рефрешит — иначе reopen зациклился бы. Поиск/фильтр/
            // страница переживают reopen (хранятся в полях активити).
            dialog.dismiss()
            showMyServersDialog()
        }
    }

    /**
     * L5-UI (ТЗ v1.4 §5): опрос прогресса ручного харвеста, пока диалог открыт. По завершении
     * пересобирает «Мои серверы» — добавленные узлы взяты в пул уже ПОСЛЕ открытия диалога, иначе
     * не показались бы (тот же приём и гейт dialog!=null, что у pollNodeCheckStatus: стартовый
     * вызов только показывает статус и не рефрешит, иначе reopen зациклился бы). Наружу приходят
     * только счётчики — мост не отдаёт сырые URL/содержимое источников.
     */
    private fun pollHarvestStatus(target: TextView, dialog: AlertDialog?, attempt: Int = 0) {
        if (dialog != null && !dialog.isShowing) return
        val p = try { JSONObject(ApfCore.harvestStatusJson()) } catch (e: Exception) { JSONObject() }
        val running = p.optBoolean("running")
        val done = p.optBoolean("done")
        val err = p.optString("error", "")
        target.text = when {
            running -> "Харвест: источник ${p.optInt("source_index")} / ${p.optInt("source_total")} · найдено ${p.optInt("found")}"
            err.isNotEmpty() -> "Харвест: $err"
            done -> {
                val merged = p.optInt("merged")
                val parsed = p.optInt("parsed")
                val subs = p.optInt("subscription_urls")
                var t = "Харвест: обработано ${p.optInt("sources_processed")}/${p.optInt("sources_total")}, добавлено новых $merged (распознано $parsed)"
                if (subs > 0) t += " · ссылок-подписок $subs (добавьте их источником вручную)"
                t
            }
            else -> ""
        }
        if (running && attempt < 600) {
            target.postDelayed({ pollHarvestStatus(target, dialog, attempt + 1) }, 1000)
        } else if (done && dialog != null && dialog.isShowing) {
            dialog.dismiss()
            showMyServersDialog()
        }
    }

    /**
     * §5 ТЗ + ТЗ v1.3 F2/F3/F4: «Мои серверы». Маркеры 📌 закреплён / ⭐ избранный / ✓ подтверждён
     * реальным трафиком / 🚫 бан; действия — подключить (через службу, без закрепления),
     * закрепить, в избранное, переименовать/заметка, бан, удалить (с надгробием — подписка не
     * вернёт; «Восстановить удалённые» снимает); обход всего списка TCP-пробой с прогрессом.
     */
    // U-3 (E2 #6, живой D7: прокрутка ~20 экранов): состояние поиска/фильтра/страницы живёт
    // в активити, а не в диалоге — диалог пересоздаётся после каждого действия над узлом
    // (reopen()), и локальные переменные каждый раз обнуляли бы и запрос, и позицию.
    private var myServersQuery: String = ""
    private var myServersFilter: Int = 0
    private var myServersLimit: Int = MY_SERVERS_PAGE

    /** Фильтры «Моих серверов». Порядок соответствует myServersFilterLabels. */
    private val myServersFilterLabels = arrayOf(
        "Все", "Подтверждённые трафиком", "Избранные", "Закреплённый", "Забаненные"
    )

    private fun showMyServersDialog() {
        var currentDialog: AlertDialog? = null
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        container.addView(infoRow(
            "Серверы, о которых APF уже что-то знает. «Подключить» — переключиться именно на " +
                "этот сервер на один раз (закрепление не меняется). «Закрепить» — авто-выбор " +
                "всегда будет предпочитать его; ⭐ «Избранное» — предпочитать после закреплённого. " +
                "«Удалить» — подписки его больше не вернут; «Бан» — никогда не выбирать " +
                "автоматически. «Сканировать все» — проверить весь список TCP-пробой без " +
                "подключения.\n\n" +
                "⭐ и 🤖 — ДВА класса избранного (W3): ⭐ добавили вы сами — снять можете " +
                "только вы. 🤖 добавила сборка каталога после пробы реального трафика — " +
                "снимется сама, если сервер перестанет давать трафик, либо нажмите ⭐ на нём, " +
                "чтобы сделать постоянным (тогда авто-снятие ему уже не грозит).\n\n" +
                "Значок слева — что известно про РЕАЛЬНЫЙ трафик через сервер:\n" +
                "✅ ${verifyBadgeText(BADGE_PROVEN_FRESH)}\n" +
                "🟢 ${verifyBadgeText(BADGE_PROVEN_STALE)}\n" +
                "⚠️ ${verifyBadgeText(BADGE_PROVEN_FAILED)}\n" +
                "🟡 ${verifyBadgeText(BADGE_TCP_ALIVE)}\n" +
                "🔴 ${verifyBadgeText(BADGE_DEAD)}\n" +
                "⚪ ${verifyBadgeText(BADGE_UNCHECKED)}\n\n" +
                "Жёлтый — САМЫЙ ЧАСТЫЙ и он НЕ означает «трафика нет». Обычное сканирование " +
                "списка («Сканировать все») только звонит на порт сервера; пропускает ли он " +
                "трафик, узнаётся при реальном подключении через него, либо кнопкой " +
                "«📡 Собрать список рабочих узлов» ниже — она проверяет реальный выход в " +
                "интернет через каждый сервер по отдельности, без полного подключения " +
                "устройства. После такой проверки отметка «выход в интернет проверен» " +
                "означает, что трафик действительно прошёл — это НЕ проверка через ваш " +
                "VPN-туннель, а отдельная быстрая проба."
        ))

        val scanStatus = TextView(this).apply {
            setTextColor(getColor(android.R.color.darker_gray))
            textSize = 12f
        }
        val scanRow = FlowLayout(this).apply {
            setPadding(0, 8, 0, 8)
        }
        scanRow.addView(Button(this).apply {
            text = "🔎 Сканировать все"
            setOnClickListener {
                val err = ApfCore.startSweep()
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_sweep, bridgeErrorText(err)))
                } else {
                    // 2026-09-22: держит операцию живой при свёрнутом приложении/погашенном
                    // экране (foreground-сервис + wake lock, см. LongOpForegroundService).
                    LongOpForegroundService.ensureStarted(this@MainActivity)
                    pollScanProgress(scanStatus, currentDialog)
                }
            }
        })
        scanRow.addView(Button(this).apply {
            text = "■ Стоп"
            setOnClickListener { ApfCore.cancelSweep() }
        })
        // U-4 (E2 §2): иконка без подписи среди прочих кнопок читалась как «непонятно что» —
        // «♻» рядом со «Сканировать все» и «Стоп» ничем не намекала на восстановление
        // удалённых. Подпись добавлена, contentDescription — для TalkBack.
        scanRow.addView(Button(this).apply {
            text = getString(R.string.btn_restore_removed)
            contentDescription = getString(R.string.btn_restore_removed)
            setOnClickListener {
                val n = ApfCore.restoreRemovedNodes()
                toast(getString(R.string.t_restored_removed, n))
            }
        })
        // P2 (ТЗ v1.6): помощь у быстрого TCP-скана — честно, что он подтверждает лишь «на связи».
        scanRow.addView(infoIcon(
            "«Сканировать все» — быстрая проверка всего списка по TCP: отвечает ли порт узла. Это " +
            "быстро, но подтверждает лишь «узел на связи», а не «через него работает интернет». Чтобы " +
            "проверить реальный выход в сеть, запустите «Собрать список рабочих узлов» ниже."
        ))
        container.addView(scanRow)
        container.addView(scanStatus)
        pollScanProgress(scanStatus, null)

        // Fix B (ТЗ v1.7 PROBE-DEPTH-SETTING): глубина пробы трафиком — паритет с desktop (там
        // настройка «Глубина проверки узлов трафиком» уже есть; на телефоне её не было). Сколько
        // верхних по TCP-рангу узлов проверять при «Собрать список рабочих узлов» ниже. Значение —
        // models.AppConfig.NodeCheckTopN через мост (валидация/персист на стороне ядра). Размещено
        // рядом с кнопкой, на которую влияет.
        // «Все рабочие» = models.NodeCheckTopNAll (config_normalize.go): проверять ВЕСЬ пул
        // рабочих узлов без верхнего среза (запрос владельца 09-15 — узел с трафиком может
        // ранжироваться ниже числового потолка и тогда не пробуется никогда). Мост шлёт это
        // значение как обычный node_check_top_n; ядро пропускает его мимо клампа 10–300.
        // Держим локальную копию числа (Kotlin не видит Go-константу) — комментарий связывает их.
        val depthAll = 1_000_000_000
        val depthValues = intArrayOf(30, 50, 100, 150, 200, 300, depthAll)
        val depthLabels = arrayOf("30 — быстро (по умолчанию)", "50", "100", "150", "200", "300 — максимум", "Все рабочие (дольше всех)")
        val depthRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, 8, 0, 8)
        }
        depthRow.addView(TextView(this).apply {
            text = "Глубина проверки узлов: "
            textSize = 14f
        })
        val depthSpinner = Spinner(this)
        depthSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, depthLabels)
        // Инициализация из конфига (0 = встроенный дефолт 30). Берём первый пресет >= текущего.
        val curDepth = ApfCore.getNodeCheckTopN().let { if (it <= 0) 30 else it }
        depthSpinner.setSelection(depthValues.indexOfFirst { it >= curDepth }.let { if (it < 0) 0 else it })
        depthSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            private var first = true
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (first) { first = false; return } // пропускаем стартовое событие setSelection
                val err = ApfCore.setNodeCheckTopN(depthValues[position])
                if (err.isNotEmpty()) toast("Глубина проверки: " + bridgeErrorText(err))
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        depthRow.addView(depthSpinner)
        depthRow.addView(infoIcon(
            "Сколько верхних по TCP-рангу узлов проверять реальным трафиком при «Собрать список " +
            "рабочих узлов». Больше узлов — выше шанс найти рабочие, но проверка идёт дольше. " +
            "«Все рабочие» проверяет весь пул целиком (узел с трафиком может стоять ниже потолка) — " +
            "это самый полный, но и самый долгий режим; проверку можно прервать кнопкой отмены."
        ))
        container.addView(depthRow)

        // ТЗ v1.5 N-3: «Собрать список рабочих узлов» — Stage 2 (реальный HTTP-трафик через
        // топ-N кандидатов), в дополнение к Stage 1 «Сканировать все» (TCP) выше. Единое имя
        // действия — см. UI_CONTRACT_v1.4 §1.1 (то же имя, что и у Web/Wails кнопки этого лота).
        val nodeCheckStatus = TextView(this).apply {
            setTextColor(getColor(android.R.color.darker_gray))
            textSize = 12f
        }
        val nodeCheckRow = FlowLayout(this).apply {
            setPadding(0, 8, 0, 8)
        }
        nodeCheckRow.addView(Button(this).apply {
            text = "📡 Собрать список рабочих узлов"
            setOnClickListener {
                val err = ApfCore.startNodeCheck()
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_node_check, bridgeErrorText(err)))
                } else {
                    // 2026-09-22: см. LongOpForegroundService — держит пробу живой при
                    // свёрнутом приложении/погашенном экране.
                    LongOpForegroundService.ensureStarted(this@MainActivity)
                    pollNodeCheckStatus(nodeCheckStatus, currentDialog)
                }
            }
        })
        nodeCheckRow.addView(Button(this).apply {
            text = "■ Стоп"
            setOnClickListener { ApfCore.cancelNodeCheck() }
        })
        // P2 (ТЗ v1.6, жалоба «нет везде хелпов»): тот же idiom infoIcon/showInfo, что и у
        // прочих настроек в диалогах. Объясняем, ЧЕМ проба реального трафика отличается от TCP-скана
        // и откуда берётся отметка «подтверждён трафиком».
        nodeCheckRow.addView(infoIcon(
            "«Собрать список рабочих узлов» проверяет РЕАЛЬНЫЙ трафик: прогоняет через каждый узел " +
            "настоящий запрос в интернет и подтверждает, что через него действительно есть выход в сеть. " +
            "Именно отсюда у узла появляется отметка «подтверждён трафиком». Это надёжнее кнопки " +
            "«Сканировать все»: та лишь быстро проверяет, отвечает ли порт узла (TCP), но выход в интернет " +
            "не гарантирует."
        ))
        container.addView(nodeCheckRow)
        container.addView(nodeCheckStatus)
        pollNodeCheckStatus(nodeCheckStatus, null)

        // L5-UI (ТЗ v1.4 §5): «Обновить узлы (харвест)» — обойти НАСТРОЕННЫЕ источники, снять
        // ссылки узлов и добавить новые в пул НЕПРОВЕРЕННЫМИ (рабочими их делает проба выше/скан).
        // Паритет с Web/Wails кнопкой этого лота (UI_CONTRACT: единое имя действия).
        val harvestStatus = TextView(this).apply {
            setTextColor(getColor(android.R.color.darker_gray))
            textSize = 12f
        }
        val harvestRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 8, 0, 8)
        }
        harvestRow.addView(Button(this).apply {
            text = "🌾 Обновить узлы (харвест)"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                val err = ApfCore.harvestNow()
                if (err.isNotEmpty()) {
                    showErrorMessage("Харвест: " + bridgeErrorText(err))
                } else {
                    // 2026-09-22: см. LongOpForegroundService — держит харвест живым при
                    // свёрнутом приложении/погашенном экране.
                    LongOpForegroundService.ensureStarted(this@MainActivity)
                    pollHarvestStatus(harvestStatus, currentDialog)
                }
            }
        })
        harvestRow.addView(infoIcon(
            "«Обновить узлы (харвест)» скачивает уже настроенные вами источники (подписки/каналы/" +
            "страницы), находит в них ссылки узлов и добавляет новые в список НЕПРОВЕРЕННЫМИ. " +
            "Работоспособность подтверждает «Собрать список рабочих узлов» или подключение. За " +
            "подписками по найденным ссылкам харвест сам в интернет не ходит: если такие встретятся, " +
            "покажет их число, чтобы вы добавили источником вручную."
        ))
        container.addView(harvestRow)
        container.addView(harvestStatus)

        // Извлечение узлов из ВСТАВЛЕННОГО ТЕКСТА: несколько ссылок сразу / дамп из Telegram или
        // страницы / base64- или Clash-подписка. Тот же детерминированный харвестер, что и кнопка
        // выше, но тело приносит сам пользователь (в интернет не ходит). Итог/прогресс — общий
        // harvestStatus (единый single-flight с обычным харвестом).
        val harvestTextInput = EditText(this).apply {
            hint = "Вставьте ссылки (vless:// vmess:// ss:// trojan://), base64-подписку или дамп"
            setSingleLine(false)
            minLines = 2
            maxLines = 5
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        val harvestTextRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 0, 0, 8)
        }
        harvestTextRow.addView(Button(this).apply {
            text = "🔎 Извлечь узлы из текста"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                val txt = harvestTextInput.text.toString().trim()
                if (txt.isEmpty()) {
                    showErrorMessage("Вставьте текст со ссылками на узлы")
                    return@setOnClickListener
                }
                val err = ApfCore.harvestFromText(txt)
                if (err.isNotEmpty()) {
                    showErrorMessage("Харвест из текста: " + bridgeErrorText(err))
                } else {
                    // 2026-09-22: см. LongOpForegroundService — держит харвест живым при
                    // свёрнутом приложении/погашенном экране.
                    LongOpForegroundService.ensureStarted(this@MainActivity)
                    pollHarvestStatus(harvestStatus, currentDialog)
                }
            }
        })
        harvestTextRow.addView(infoIcon(
            "«Извлечь узлы из текста» разбирает то, что вы вставили в поле выше: несколько ссылок " +
            "сразу, дамп из Telegram или со страницы, base64- или Clash-подписку. Разбор " +
            "детерминированный, без ИИ, и в интернет он не ходит — ссылки-подписки (http-адреса) " +
            "не скачиваются, их нужно добавить источником вручную. Найденные узлы входят " +
            "НЕПРОВЕРЕННЫМИ: работоспособность подтверждает «Собрать список рабочих узлов» или подключение."
        ))
        container.addView(harvestTextInput)
        container.addView(harvestTextRow)

        pollHarvestStatus(harvestStatus, null)

        // U-17 (C-4): отказ записи узлов на диск виден РЯДОМ СО СПИСКОМ узлов, а не только
        // в Диагностике — иначе пользователь правит список, а правки не переживают перезапуск.
        persistWarningText()?.let { warn ->
            container.addView(TextView(this).apply {
                text = warn
                setTextColor(0xFFF5A623.toInt())
                textSize = 12f
                setPadding(0, 8, 0, 8)
            })
        }

        fun reopen() {
            currentDialog?.dismiss()
            showMyServersDialog()
        }

        // ─── U-3: поиск, фильтр, постраничная подгрузка ───────────────────────
        //
        // Живой прогон D7: 5467 узлов одним сплошным списком по 6 кнопок на строку —
        // ~20 экранов прокрутки, найти конкретный сервер нельзя. Поиск идёт по имени
        // (в нём же и адрес, и код страны — метка каталога вида «🇬🇧GB-82.38.31.179-0124»)
        // и по заметке пользователя; фильтр — по тем же признакам, что уже показывает значок.
        val etSearch = EditText(this).apply {
            hint = getString(R.string.my_servers_search_hint)
            setText(myServersQuery)
            setSingleLine()
        }
        container.addView(etSearch)
        val spFilter = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity, android.R.layout.simple_spinner_dropdown_item,
                myServersFilterLabels
            )
            setSelection(myServersFilter.coerceIn(0, myServersFilterLabels.size - 1))
        }
        // P1-1 (ТЗ v1.6): фильтр применяется СРАЗУ при выборе в спиннере, а не только по кнопке
        // «Найти» (жалоба «фильтр не срабатывает»). Гейт pos != myServersFilter гасит стартовый
        // авто-вызов onItemSelected: setSelection выше вызывает его с уже текущим значением.
        spFilter.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, pos: Int, id: Long) {
                if (pos == myServersFilter) return
                myServersQuery = etSearch.text.toString().trim()
                myServersFilter = pos
                myServersLimit = MY_SERVERS_PAGE
                reopen()
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        // P2 (ТЗ v1.6): спиннер фильтра + помощь в одной строке — объясняем каждый вариант фильтра
        // и что список всегда идёт «подтверждёнными вперёд» (P1-1). infoIcon вынесен рядом со
        // спиннером, а не внутрь него, чтобы тап по «ⓘ» не открывал выпадающий список.
        val filterRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
        }
        filterRow.addView(spFilter, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        filterRow.addView(infoIcon(
            "Фильтр списка. «Подтверждённые трафиком» — только узлы, у которых успешно прошла проба " +
            "реального трафика (кнопка «Собрать список рабочих узлов» выше). «Избранные» и «Закреплённый» — " +
            "отмеченные вами вручную. «Забаненные» — временно исключённые из автоподбора. Список всегда " +
            "показывает подтверждённые узлы первыми."
        ))
        container.addView(filterRow)
        container.addView(Button(this).apply {
            text = getString(R.string.my_servers_find)
            setOnClickListener {
                myServersQuery = etSearch.text.toString().trim()
                myServersFilter = spFilter.selectedItemPosition
                myServersLimit = MY_SERVERS_PAGE
                reopen()
            }
        })

        val allNodes = try {
            JSONArray(ApfCore.nodesJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор списка серверов: $e")
            JSONArray()
        }
        if (allNodes.length() == 0) {
            container.addView(TextView(this).apply {
                text = "Список пуст — добавьте сервер по ссылке на главном экране " +
                    "или через «Каталог серверов»"
                setTextColor(getColor(android.R.color.darker_gray))
            })
        }
        val query = myServersQuery.lowercase()
        var nodes = JSONArray()
        for (i in 0 until allNodes.length()) {
            val n = allNodes.optJSONObject(i) ?: continue
            val haystack = (n.optString("name") + " " + n.optString("note") + " " +
                n.optString("protocol")).lowercase()
            if (query.isNotEmpty() && !haystack.contains(query)) continue
            val keep = when (myServersFilter) {
                1 -> n.optBoolean("proven")
                2 -> n.optBoolean("favorite")
                3 -> n.optBoolean("pinned")
                4 -> n.optBoolean("banned")
                else -> true
            }
            if (keep) nodes.put(n)
        }
        // P1-1 (ТЗ v1.6): «сортировка по проверенным трафиком» — стабильно поднимаем узлы с
        // подтверждённым реальным трафиком (proven) наверх, сохраняя прежний порядок внутри групп.
        // Раньше сортировки по проверенности не было вовсе (жалоба живого прогона).
        run {
            val sorted = (0 until nodes.length()).mapNotNull { nodes.optJSONObject(it) }
                .sortedByDescending { it.optBoolean("proven") }
            val rebuilt = JSONArray()
            sorted.forEach { rebuilt.put(it) }
            nodes = rebuilt
        }
        if (allNodes.length() > 0 && nodes.length() == 0) {
            container.addView(TextView(this).apply {
                text = getString(R.string.my_servers_nothing_found)
                setTextColor(getColor(android.R.color.darker_gray))
                setPadding(0, 12, 0, 12)
            })
        }
        val shown = minOf(myServersLimit, nodes.length())
        if (nodes.length() > 0) {
            container.addView(TextView(this).apply {
                text = getString(R.string.my_servers_shown, shown, nodes.length())
                setTextColor(getColor(android.R.color.darker_gray))
                textSize = 12f
                setPadding(0, 8, 0, 8)
            })
        }
        // W3: один запрос на весь диалог, а не по одному на строку (список может показывать
        // до MY_SERVERS_PAGE серверов) — тот же приём, что и у самого списка узлов (allNodes
        // выше берётся одним JSON, не по одному вызову моста на сервер).
        val systemFavoriteIds = try {
            val arr = JSONArray(ApfCore.systemFavoriteIdsJson())
            (0 until arr.length()).map { arr.optString(it) }.toSet()
        } catch (e: Exception) {
            emptySet<String>()
        }
        for (i in 0 until shown) {
            val node = nodes.optJSONObject(i) ?: continue
            val id = node.optString("id")
            val name = node.optString("name", id)
            val pinned = node.optBoolean("pinned")
            val favorite = node.optBoolean("favorite")
            // W3 (ТЗ v1.5 §2): избранное делится на класс "user" (звезда, sticky) и "system"
            // (сборка каталога после пробы трафика) — см. FavoriteOrigin/UserFavoriteIDsJSON/
            // SystemFavoriteIDsJSON в bridge.go. node.favorite (любого класса) уже приходит в
            // GetNodesJSON; принадлежность к системному классу проверяем по отдельному набору.
            val isSystemFavorite = favorite && systemFavoriteIds.contains(id)
            val proven = node.optBoolean("proven")
            val banned = node.optBoolean("banned")
            val note = node.optString("note")
            // Значок проверенности считает Go-сторона одним общим правилом для всех трёх UI
            // (models.Node.VerifyBadge). Раньше здесь было ДВА независимых маркера — цветная
            // точка по TCP-статусу и галочка «✓» по булеву proven, — и они противоречили друг
            // другу: зелёная точка у узла, через который трафик не проходил ни разу, читалась
            // как «работает». Фолбэк ниже нужен на случай старого apf.aar без поля.
            val badge = node.optString("verify_badge").ifEmpty {
                when {
                    proven -> BADGE_PROVEN_STALE
                    node.optString("status") == "ok" || node.optString("status") == "slow" -> BADGE_TCP_ALIVE
                    node.optString("status").isEmpty() -> BADGE_UNCHECKED
                    else -> BADGE_DEAD
                }
            }
            val lastVerifiedAt = node.optLong("last_verified_at", 0L)
            val verifiedCount = node.optInt("verified_count", 0)
            val verifiedLatency = node.optInt("verified_latency_ms", 0)

            val block = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, 16, 0, 16)
                if (banned) alpha = 0.55f
            }
            block.addView(TextView(this).apply {
                // W3: 🤖 — системный фаворит (авто, по пробе трафика), отдельно от ⭐
                // пользовательского — тот же значок, что и в легенде диалога выше.
                val favoriteIcon = when {
                    isSystemFavorite -> "🤖 "
                    favorite -> "⭐ "
                    else -> ""
                }
                text = "${verifyBadgeIcon(badge)} ${if (pinned) "📌 " else ""}$favoriteIcon" +
                    "${if (banned) "🚫 " else ""}$name" +
                    (if (note.isNotEmpty()) " — $note" else "")
                setTextColor(getColor(android.R.color.white))
            })
            block.addView(TextView(this).apply {
                // Подпись значка — словами, не только цветом: «жёлтый» сам по себе читается
                // как «плохо», хотя означает «через этот сервер трафик не проверялся».
                // C-20 (ТЗ v1.4): «через туннель» здесь БОЛЬШЕ НЕ ПИШЕТСЯ. Замер
                // last_verified_latency_ms почти всегда сделан через локальный SOCKS5
                // (проба №1 post-connect), а в режиме «Прокси» TUN нет вовсе — называть
                // это «через туннель» значило бы утверждать то, чего замер не доказывает.
                // Чем именно он получен, знает поле last_verified_via, но в облегчённом
                // списке узлов моста (GetNodesJSON) его пока нет — поэтому здесь стоит
                // нейтральная и всегда верная формулировка «до выхода» (UI_CONTRACT §2.4
                // допускает её наравне с «через прокси-канал узла»). См. bridge_requests
                // в result.json лота: как только поле появится в списке, подпись станет
                // такой же точной, как у активного узла на главном экране.
                val latencyPart = if (verifiedLatency > 0) {
                    getString(R.string.latency_exit, verifiedLatency)
                } else {
                    getString(R.string.latency_tcp, node.optInt("latency_ms"))
                }
                val freshness = verifiedAgeLabel(lastVerifiedAt, verifiedCount)
                text = "${node.optString("protocol")} · $latencyPart\n" +
                    verifyBadgeText(badge) + freshness
                setTextColor(getColor(android.R.color.darker_gray))
                textSize = 12f
            })
            val actionRow = FlowLayout(this).apply {
                setPadding(0, 8, 0, 0)
            }
            actionRow.addView(Button(this).apply {
                text = "Подключить"
                isEnabled = !banned
                setOnClickListener {
                    connectToNodeViaService(id, name)
                    currentDialog?.dismiss()
                }
            })
            actionRow.addView(Button(this).apply {
                text = if (pinned) "Открепить" else "Закрепить"
                setOnClickListener {
                    val err = if (pinned) ApfCore.unpinNode() else ApfCore.pinNode(id)
                    if (err.isNotEmpty()) {
                        showErrorMessage(getString(R.string.e_pin, bridgeErrorText(err)))
                    } else {
                        toast(
                            if (pinned) getString(R.string.t_unpinned, name)
                            else getString(R.string.t_pinned, name)
                        )
                        reopen()
                    }
                }
            })
            actionRow.addView(Button(this).apply {
                // U-4: у значка есть подпись — «⭐» без слов не отличалось от индикатора.
                // W3: на СИСТЕМНОМ фаворите эта же кнопка вызывает addFavorite, которая
                // ПОВЫШАЕТ существующую системную запись до пользовательской (sticky
                // promotion, engine.addFavoriteWithOrigin) — это смена класса той же записи,
                // а не повторное добавление. Убрать системный фаворит БЕЗ повышения можно
                // отдельной кнопкой «✕ Убрать» ниже.
                text = when {
                    isSystemFavorite -> "🤖 Сделать постоянным"
                    favorite -> "⭐ Из избранного"
                    else -> "☆ В избранное"
                }
                contentDescription = when {
                    isSystemFavorite -> getString(R.string.cd_system_favorite_promote)
                    favorite -> "Убрать из избранного"
                    else -> "Добавить в избранное"
                }
                setOnClickListener {
                    val err = if (favorite && !isSystemFavorite) ApfCore.removeFavorite(id) else ApfCore.addFavorite(id)
                    if (err.isNotEmpty()) {
                        showErrorMessage(getString(R.string.e_favorite, bridgeErrorText(err)))
                    } else {
                        reopen()
                    }
                }
            })
            if (isSystemFavorite) {
                // W3: «User can remove both» — системный фаворит снять может и пользователь,
                // не только реконсиляция каталога сама (когда проба перестаёт подтверждать
                // трафик). Отдельная кнопка, чтобы не путать «убрать совсем» со «сделать
                // постоянным» выше — обе ведут к разным классам/состояниям одной записи.
                actionRow.addView(Button(this).apply {
                    text = "✕ Убрать"
                    contentDescription = getString(R.string.cd_system_favorite_remove)
                    setOnClickListener {
                        val err = ApfCore.removeFavorite(id)
                        if (err.isNotEmpty()) {
                            showErrorMessage(getString(R.string.e_favorite, bridgeErrorText(err)))
                        } else {
                            reopen()
                        }
                    }
                })
            }
            block.addView(actionRow)

            val manageRow = FlowLayout(this).apply {
                setPadding(0, 4, 0, 0)
            }
            manageRow.addView(Button(this).apply {
                // U-4: «✏» без подписи стояла среди шести кнопок и читалась как украшение.
                text = getString(R.string.btn_edit_node)
                contentDescription = getString(R.string.btn_edit_node)
                setOnClickListener { showEditNodeDialog(id, name, note) { reopen() } }
            })
            manageRow.addView(Button(this).apply {
                text = if (banned) "♻ Разбанить" else "🚫 Бан"
                setOnClickListener {
                    if (banned) {
                        val err = ApfCore.banNode(id, false)
                        if (err.isNotEmpty()) {
                            showErrorMessage(getString(R.string.e_ban, bridgeErrorText(err)))
                        } else {
                            reopen()
                        }
                    } else {
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("Забанить «$name»?")
                            .setMessage("Сервер никогда не будет выбираться автоматически. Снять бан можно здесь же.")
                            .setPositiveButton("Забанить") { _, _ ->
                                val err = ApfCore.banNode(id, true)
                                if (err.isNotEmpty()) {
                                    showErrorMessage(getString(R.string.e_ban, bridgeErrorText(err)))
                                } else {
                                    reopen()
                                }
                            }
                            .setNegativeButton("Отмена", null)
                            .show()
                    }
                }
            })
            manageRow.addView(Button(this).apply {
                text = "🗑 Удалить"
                contentDescription = "Удалить сервер"
                setOnClickListener {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Удалить «$name»?")
                        .setMessage(
                            "Сервер исчезнет из списка, подписки его больше не вернут. " +
                                "Отменить можно кнопкой «♻ Восстановить удалённые» вверху списка."
                        )
                        .setPositiveButton("Удалить") { _, _ ->
                            val err = ApfCore.removeNode(id)
                            if (err.isNotEmpty()) {
                                showErrorMessage(getString(R.string.e_remove_node, bridgeErrorText(err)))
                            } else {
                                reopen()
                            }
                        }
                        .setNegativeButton("Отмена", null)
                        .show()
                }
            })
            block.addView(manageRow)
            container.addView(block)
        }

        // U-3: постраничная подгрузка вместо одного сплошного списка на тысячи строк.
        if (nodes.length() > shown) {
            container.addView(Button(this).apply {
                text = getString(R.string.my_servers_more)
                setOnClickListener {
                    myServersLimit += MY_SERVERS_PAGE
                    reopen()
                }
            })
        }

        currentDialog = AlertDialog.Builder(this)
            .setTitle("Мои серверы")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton(getString(R.string.btn_close), null)
            .show()
    }

    /** Правка имени/заметки узла (ТЗ v1.3 F3). Пустое имя — не менять, пустая заметка — убрать. */
    private fun showEditNodeDialog(id: String, name: String, note: String, onDone: () -> Unit) {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 16, 48, 0)
        }
        val etName = EditText(this).apply { hint = "Название"; setText(name) }
        val etNote = EditText(this).apply { hint = "Заметка (пусто — убрать)"; setText(note) }
        box.addView(etName)
        box.addView(etNote)
        AlertDialog.Builder(this)
            .setTitle("Правка сервера")
            .setView(box)
            .setPositiveButton("Сохранить") { _, _ ->
                val patch = JSONObject()
                    .put("name", etName.text.toString().trim())
                    .put("user_note", etNote.text.toString().trim())
                val err = ApfCore.updateNode(id, patch.toString())
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_edit_node, bridgeErrorText(err)))
                } else {
                    onDone()
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    /**
     * Опрашивает счётчик доменов AdBlock после смены профиля и обновляет `target` на
     * месте — найдено QA 2026-08-17: `SetAdBlockProfile` в движке запускает загрузку
     * блок-листов в отдельной горутине и не ждёт её (см. комментарий у showAdBlockDialog),
     * поэтому "Доменов в списках" оставалось 0 сколько угодно долго при открытом диалоге —
     * счётчик читался один раз, при первом построении диалога. Останавливается сама, как
     * только число стало ненулевым (загрузка реально завершилась), или после 20 попыток
     * (~40с — с запасом больше типичного времени загрузки листов).
     */
    private fun pollAdBlockDomainCount(target: TextView, attempt: Int = 0) {
        if (attempt >= 20 || isFinishing) return
        target.postDelayed({
            if (isFinishing) return@postDelayed
            val status = try { JSONObject(ApfCore.adBlockStatusJson()) } catch (e: Exception) { null }
            val count = status?.optInt("total_domains") ?: 0
            target.text = "Доменов в списках: $count"
            if (count == 0) pollAdBlockDomainCount(target, attempt + 1)
        }, 2000)
    }

    /**
     * Э-UI-3 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.3). ApfCore.adBlockStatusJson/
     * setAdBlockProfile/adBlockToggleAllowlist уже в мосте (internal/adblock на
     * бэкенде полностью работает и открыт на десктопе, эндпоинты /api/adblock/...) —
     * на Android не было ни моста, ни экрана вообще.
     *
     * Профиль выбирается спиннером (тот же виджет, что уже применён для Sticky
     * Session) — смена сразу уходит в бридж; загрузка блок-листов для НЕ-disabled
     * профиля идёт в фоне на движке (до 2 минут), диалог её не ждёт. Белый список
     * отрисовывается построчно (тот же принцип, что и провайдеры в
     * showCatalogDialog — записей единицы, отдельный адаптер избыточен), каждая
     * строка с собственной кнопкой удаления.
     */
    private fun showAdBlockDialog() {
        val status = try {
            JSONObject(ApfCore.adBlockStatusJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор статуса AdBlock: $e")
            JSONObject()
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }

        val profileValues = arrayOf("disabled", "light", "standard", "strict")
        val profileLabels = arrayOf(
            "Выключено", "Лёгкий — только реклама",
            "Стандарт — реклама и трекеры", "Строгий — и телеметрия"
        )
        container.addView(TextView(this).apply {
            text = "Профиль блокировки"
            setPadding(0, 0, 0, 8)
        })
        container.addView(infoRow(
            "Блокировка рекламы и трекеров на уровне DNS активного подключения: «Выключено» — ничего " +
            "не режем; «Лёгкий» — только рекламные домены; «Стандарт» — реклама и трекеры; «Строгий» — " +
            "плюс телеметрия. Чем строже профиль, тем больше доменов в списках, но и выше шанс, что " +
            "какой-то сайт недосчитается части содержимого. Если сайт сломался — ослабьте профиль."
        ))
        val spinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity, android.R.layout.simple_spinner_dropdown_item, profileLabels
            )
        }
        val startIndex = profileValues.indexOf(status.optString("profile", "disabled"))
        spinner.setSelection(if (startIndex < 0) 0 else startIndex)
        // Спиннер вызывает onItemSelected сразу при setSelection — без этого флага
        // первое же открытие диалога отправило бы в бридж уже применённый профиль
        // (ложная, но безвредная запись); с флагом реагируем только на выбор ПОСЛЕ
        // открытия. K2-A: тот же приём теперь и в initStickySessionSpinner — там он
        // стал нужен ровно тогда, когда спиннер начал показывать применённую политику
        // (до этого он всегда стоял на первой строке, и «ложная запись» была не
        // безвредной, а стирала выбор пользователя).
        val tvDomainCount = TextView(this).apply {
            text = "Доменов в списках: ${status.optInt("total_domains")}"
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 12, 0, 24)
        }

        var spinnerReady = false
        spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (!spinnerReady) { spinnerReady = true; return }
                val newProfile = profileValues[position]
                val err = ApfCore.setAdBlockProfile(newProfile)
                if (err.isEmpty()) {
                    toast(getString(R.string.t_adblock_profile_changed))
                } else {
                    showErrorMessage(getString(R.string.e_adblock, bridgeErrorText(err)))
                }
                if (err.isEmpty() && newProfile != "disabled") pollAdBlockDomainCount(tvDomainCount)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        container.addView(spinner)
        container.addView(tvDomainCount)

        container.addView(TextView(this).apply {
            text = "Белый список (не блокировать)"
            setPadding(0, 0, 0, 8)
        })
        val etDomain = EditText(this).apply { hint = "example.com" }
        container.addView(etDomain)
        container.addView(Button(this).apply {
            text = "Добавить"
            setOnClickListener {
                val domain = etDomain.text.toString().trim()
                if (domain.isEmpty()) return@setOnClickListener
                ApfCore.adBlockToggleAllowlist(domain, true)
                etDomain.text.clear()
                toast(getString(R.string.t_allowlist_added, domain))
            }
        })

        val allowlist = status.optJSONArray("allowlist") ?: JSONArray()
        for (i in 0 until allowlist.length()) {
            val domain = allowlist.optString(i)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(0, 12, 0, 0)
            }
            row.addView(TextView(this).apply {
                text = domain
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(Button(this).apply {
                text = "Убрать"
                setOnClickListener {
                    ApfCore.adBlockToggleAllowlist(domain, false)
                    toast(getString(R.string.t_allowlist_removed, domain))
                    container.removeView(row)
                }
            })
            container.addView(row)
        }

        AlertDialog.Builder(this)
            .setTitle("Блокировка рекламы")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    /**
     * Э-UI-4 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.4). ApfCore.leakGuardStatusJson/
     * runDnsLeakTestJson/setWebRTCBlock уже в мосте (internal/leakguard на бэкенде
     * полностью работает и открыт на десктопе) — на Android был только IPv6 Block
     * (уже на главном экране, swIpv6). WebRTC-защита и DNS-leak тест отсутствовали.
     *
     * runDnsLeakTestJson БЛОКИРУЕТ вызывающий поток на время реального теста
     * (~8, таймаут 15 секунд) — вызов из onClickListener напрямую заморозил бы
     * интерфейс и, скорее всего, поймал бы ANR. Запускается в отдельном
     * `Thread`, результат возвращается в интерфейс через `runOnUiThread` — тот
     * же принцип, каким остальной код уже переносит колбэки из Go-слоя на
     * главный поток (onLog/onStateChanged в APFVpnService).
     */
    private fun showPrivacyDialog() {
        val status = try {
            JSONObject(ApfCore.leakGuardStatusJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор статуса приватности: $e")
            JSONObject()
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }

        val webrtcRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, 16)
        }
        webrtcRow.addView(TextView(this).apply {
            text = "Блокировка WebRTC"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        webrtcRow.addView(infoIcon(
            "WebRTC может раскрыть ваш реальный IP-адрес в обход VPN даже при активном " +
                "туннеле — известная уязвимость браузеров. Блокировка отключает эту " +
                "возможность на уровне сети; часть WebRTC-функций сайтов (видеозвонки в " +
                "браузере) при этом может перестать работать."
        ))
        // U-16 (ТЗ v1.4, UI_CONTRACT §4.2 п.6 и §4.3): ЕДИНСТВЕННОЕ из шести опасных действий
        // E2, которое не имело подтверждения НИ В ОДНОМ из трёх интерфейсов. Kill Switch,
        // IPv6 Block и шифрование кэша получили диалог ещё в K2-A; WebRTC — тот же класс
        // риска (утечка реального IP в обход живого туннеля), а выключался одним тапом молча.
        //
        // Положение тумблера читается тем же трёхзначным путём, что и на главном экране
        // (см. toggleChecked ниже): leakGuardStatusJson отвечает осмысленно только при
        // поднятом ядре, поэтому он здесь — резервное значение, а не источник истины.
        //
        // Именованная переменная под слушателя (тот же приём, что в showCatalogDialog):
        // «Отмена» обязана вернуть тумблер во ВКЛ, а вернуть его, не вызвав слушателя
        // повторно, можно только сняв и снова навесив ЭТОТ ЖЕ экземпляр.
        val swWebRTC = Switch(this)
        lateinit var webrtcListener: CompoundButton.OnCheckedChangeListener
        fun restoreWebRTC(view: CompoundButton, checked: Boolean) {
            view.setOnCheckedChangeListener(null)
            view.isChecked = checked
            view.setOnCheckedChangeListener(webrtcListener)
        }
        fun applyWebRTC(view: CompoundButton, enabled: Boolean) {
            val err = ApfCore.setWebRTCBlock(enabled)
            if (err.isEmpty()) return
            showErrorMessage(getString(R.string.e_webrtc, bridgeErrorText(err)))
            restoreWebRTC(view, !enabled)
        }
        webrtcListener = CompoundButton.OnCheckedChangeListener { view, checked ->
            if (checked) {
                // Включение защиты — без вопроса (UI_CONTRACT §4.1): спрашивать «вы уверены?»
                // на действии, которое делает пользователя безопаснее, значит учить его
                // отмахиваться от диалогов.
                applyWebRTC(view, true)
            } else {
                confirmDisableProtection(
                    title = "Выключить блокировку WebRTC?",
                    message = "WebRTC может раскрыть ваш реальный IP-адрес в обход VPN даже " +
                        "при активном туннеле — известная уязвимость браузеров. Без блокировки " +
                        "часть сайтов сможет узнать ваше настоящее местоположение; часть " +
                        "функций сайтов (видеозвонки в браузере) при этом будет работать как " +
                        "обычно.",
                    onConfirm = { applyWebRTC(view, false) },
                    onCancel = { restoreWebRTC(view, true) }
                )
            }
        }
        // C-13: тот же трёхзначный опрос, что и у тумблеров главного экрана. leakGuardStatus
        // читается только при поднятом ядре, поэтому он здесь — резервное значение, а не
        // источник истины.
        swWebRTC.isChecked = toggleChecked(
            TOGGLE_WEBRTC_BLOCK, status.optBoolean("webrtc_guard_enabled")
        )
        swWebRTC.setOnCheckedChangeListener(webrtcListener)
        webrtcRow.addView(swWebRTC)
        container.addView(webrtcRow)

        val tvResult = TextView(this).apply {
            text = "Нажмите «Проверить», чтобы запустить тест DNS-утечки (до 15 секунд)"
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 12, 0, 24)
        }
        container.addView(tvResult)

        val btnTest = Button(this).apply { text = "Проверить DNS-утечку" }
        btnTest.setOnClickListener {
            btnTest.isEnabled = false
            tvResult.text = "Проверка идёт…"
            Thread {
                val resultJson = ApfCore.runDnsLeakTestJson()
                runOnUiThread {
                    btnTest.isEnabled = true
                    tvResult.text = try {
                        val r = JSONObject(resultJson)
                        if (r.has("error")) {
                            "Ошибка: ${r.optString("error")}"
                        } else {
                            buildString {
                                appendLine(
                                    if (r.optBoolean("leaked")) "⚠ Утечка DNS обнаружена"
                                    else "✓ Утечек не обнаружено"
                                )
                                appendLine("Системный DNS: ${r.optString("system_dns").ifBlank { "не определён (Android не даёт приложению читать его напрямую)" }}")
                                appendLine("DNS туннеля: ${r.optString("tunnel_dns")}")
                                append(r.optString("recommendation"))
                            }
                        }
                    } catch (e: Exception) {
                        "Не удалось разобрать результат: $e"
                    }
                }
            }.start()
        }
        container.addView(btnTest)

        AlertDialog.Builder(this)
            .setTitle("Приватность")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    /**
     * Э-UI-5 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.5). internal/dpi на бэкенде
     * полностью работает и открыт на десктопе — на Android не было ни моста,
     * ни экрана. Canary-тест и автовыбор SNI ShadowTLS блокируют вызывающий
     * поток (до 25 и 15 секунд соответственно) — тот же приём Thread +
     * runOnUiThread, что уже применён в showPrivacyDialog для DNS-leak теста.
     */
    private fun showDpiDialog() {
        val status = try {
            JSONObject(ApfCore.dpiStatusJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор статуса анти-DPI: $e")
            JSONObject()
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        fun header(text: String) {
            container.addView(TextView(this).apply {
                this.text = text
                setTextColor(getColor(android.R.color.darker_gray))
                setPadding(0, 24, 0, 8)
            })
        }

        // K2-A (свод C трек 1 п.9; B1 #5, B3 #4, D6): два тумблера маскировки размера
        // пакетов сняты с экрана. Причина не в UI: вставить «мусорный» объём в пакеты
        // может только сам транспорт, а sing-box без патча вендорного кода этого не
        // умеет — движок теперь честно отдаёт padding_enabled=false. Тумблер, который
        // ничего не включает, хуже отсутствующего: пользователь считает, что защита от
        // анализа размера трафика у него есть, и принимает решения исходя из этого.
        // Раздел оставлен с честной подписью, а не удалён целиком, чтобы вернувшийся к
        // экрану пользователь понял, куда делся переключатель.
        header("Маскировка размера пакетов · не реализовано в этой сборке")
        container.addView(TextView(this).apply {
            text = "Переключатель убран. Добавление «мусорного» объёма к пакетам требует " +
                "изменений в самом sing-box — в этой сборке функция не работает, и APF " +
                "больше не делает вид, что она включена. На защиту от блокировок это не " +
                "влияет: реально работает предпочтение Reality при блокировке по SNI."
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 0, 0, 12)
        })

        // U-5 (E2 §3, словарь UI_CONTRACT §1.3 п.8): «Canary-тест» — голый термин. Название
        // действия теперь человеческое, техническое имя осталось в скобках, а рядом —
        // объяснение, включая честное предупреждение, что зонд идёт МИМО туннеля.
        header("Проверка обнаружения VPN (Canary-тест)")
        container.addView(infoRow(
            "Проверяет, видит ли провайдер, что вы используете VPN. Тест идёт мимо туннеля " +
                "специально — короткая заметность ради проверки, это нормально."
        ))
        val tvCanaryResult = TextView(this).apply {
            text = "Нажмите «Проверить», чтобы запустить тест (до 25 секунд)"
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 0, 0, 12)
        }
        container.addView(tvCanaryResult)
        val btnCanary = Button(this).apply { text = "Проверка обнаружения VPN (Canary-тест)" }
        btnCanary.setOnClickListener {
            btnCanary.isEnabled = false
            tvCanaryResult.text = "Проверка идёт…"
            Thread {
                val resultJson = ApfCore.runCanaryTestJson()
                runOnUiThread {
                    btnCanary.isEnabled = true
                    tvCanaryResult.text = try {
                        val r = JSONObject(resultJson)
                        if (r.has("error")) {
                            "Ошибка: ${r.optString("error")}"
                        } else {
                            buildString {
                                appendLine("Оценка: ${r.optInt("score")}/100")
                                appendLine(
                                    if (r.optBoolean("vpn_detectable")) "⚠ VPN может быть обнаружен"
                                    else "✓ Признаков обнаружения нет"
                                )
                                append(r.optString("recommendation"))
                            }
                        }
                    } catch (e: Exception) {
                        "Не удалось разобрать результат: $e"
                    }
                }
            }.start()
        }
        container.addView(btnCanary)

        header("ShadowTLS v3 (маскировка под TLS)")
        container.addView(infoRow(
            "Оборачивает VPN-соединение так, чтобы оно выглядело как обычный HTTPS к " +
                "обычному сайту (SNI) — помогает обойти блокировку по анализу протокола " +
                "(DPI). Требует пароль и SNI, совпадающие с настройками сервера — при " +
                "ошибке в них соединение просто не поднимется."
        ))
        // Задача #29, QA 2026-08-18: раньше диалог всегда открывался с пустыми полями, хотя
        // конфиг мог быть уже сохранён — узнать текущее состояние можно было только через
        // Диагностику/логкат. shadowtls_status не содержит пароль (секрет, не эхо в UI —
        // см. комментарий у Engine.SetShadowTLSConfig) — оставляем поле пароля пустым, но
        // подставляем enabled/SNI/Server. Пустой пароль при повторном сохранении УЖЕ
        // включённого ShadowTLS трактуется движком как «не меняю» (тот же фикс), поэтому
        // просто поправить SNI не потребует вводить пароль заново.
        val shadowStatus = status.optJSONObject("shadowtls_status") ?: JSONObject()
        val swShadowTLS = Switch(this).apply {
            text = "Включён"
            isChecked = shadowStatus.optBoolean("enabled")
        }
        container.addView(swShadowTLS)
        val etShadowPassword = EditText(this).apply {
            hint = if (shadowStatus.optBoolean("enabled"))
                "Пароль (оставьте пустым, чтобы не менять)" else "Пароль"
        }
        val etShadowSNI = EditText(this).apply {
            hint = "SNI, например www.microsoft.com"
            shadowStatus.optString("handshake_sni").takeIf { it.isNotEmpty() }?.let { setText(it) }
        }
        val etShadowServer = EditText(this).apply {
            hint = "SNI-сайт для проверки доступности, необязательно (host:port)"
            shadowStatus.optString("handshake_server").takeIf { it.isNotEmpty() }?.let { setText(it) }
        }
        // Тот же P1-1 (аудит 2026-09-01), что уже исправлен на десктопе/Web UI: server_addr —
        // РЕАЛЬНЫЙ адрес shadow-tls сервера (host:port), куда физически уходит соединение;
        // etShadowServer выше — необязательное переопределение SNI-сайта для проверки, к
        // маршруту трафика отношения не имеет. Раньше здесь этого поля не было вовсе — вызов
        // Androidbridge.setShadowTLSConfig не собирался бы с текущей сигнатурой (5 параметров
        // в Go-мосте), и даже если бы собрался — движок отказал бы на включении пустым
        // server_addr (см. Engine.SetShadowTLSConfig).
        val etShadowServerAddr = EditText(this).apply {
            hint = "Реальный адрес сервера (host:port) — обязателен при включении"
            shadowStatus.optString("server_addr").takeIf { it.isNotEmpty() }?.let { setText(it) }
        }
        container.addView(etShadowPassword)
        container.addView(etShadowSNI)
        container.addView(etShadowServer)
        container.addView(etShadowServerAddr)
        val tvShadowResult = TextView(this).apply {
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 8, 0, 8)
        }
        container.addView(tvShadowResult)
        container.addView(Button(this).apply {
            text = "Сохранить ShadowTLS"
            setOnClickListener {
                val err = ApfCore.setShadowTLSConfig(
                    swShadowTLS.isChecked,
                    etShadowPassword.text.toString(),
                    etShadowSNI.text.toString(),
                    etShadowServer.text.toString(),
                    etShadowServerAddr.text.toString()
                )
                if (err.isNullOrEmpty()) {
                    toast(getString(R.string.t_shadowtls_saved))
                } else {
                    showErrorMessage(getString(R.string.e_shadowtls, bridgeErrorText(err)))
                }
            }
        })
        val btnAutoSNI = Button(this).apply { text = "Автовыбор SNI" }
        btnAutoSNI.setOnClickListener {
            btnAutoSNI.isEnabled = false
            tvShadowResult.text = "Подбираю SNI…"
            Thread {
                val resultJson = ApfCore.autoSelectShadowTLSSNIJson()
                runOnUiThread {
                    btnAutoSNI.isEnabled = true
                    tvShadowResult.text = try {
                        val r = JSONObject(resultJson)
                        if (r.has("error")) {
                            "Ошибка: ${r.optString("error")}"
                        } else {
                            etShadowSNI.setText(r.optString("sni"))
                            "SNI выбран: ${r.optString("sni")}"
                        }
                    } catch (e: Exception) {
                        "Не удалось разобрать результат: $e"
                    }
                }
            }.start()
        }
        container.addView(btnAutoSNI)

        header("CDN Fronting")
        container.addView(infoRow(
            "Прячет VPN-соединение за обычным CDN (например, Cloudflare Worker) — снаружи " +
                "трафик выглядит как обращение к CDN, а не напрямую к VPN-серверу. Помогает, " +
                "если сам VPN-сервер заблокирован по IP/домену. Требует отдельно " +
                "развёрнутый worker и знание адреса реального сервера."
        ))
        // Задача #29: подставляем сохранённый конфиг CDN Fronting — ничего секретного тут
        // нет (в отличие от ShadowTLS-пароля), поэтому подставляются все три поля.
        val cdnStatus = status.optJSONObject("cdn_status") ?: JSONObject()
        val etCdnWorker = EditText(this).apply {
            hint = "worker.example.workers.dev"
            cdnStatus.optString("worker_domain").takeIf { it.isNotEmpty() }?.let { setText(it) }
        }
        val etCdnHost = EditText(this).apply {
            hint = "IP или домен сервера"
            cdnStatus.optString("backend_host").takeIf { it.isNotEmpty() }?.let { setText(it) }
        }
        val etCdnPort = EditText(this).apply {
            hint = "Порт (обычно 443)"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            cdnStatus.optInt("backend_port").takeIf { it > 0 }?.let { setText(it.toString()) }
        }
        container.addView(etCdnWorker)
        container.addView(etCdnHost)
        container.addView(etCdnPort)
        container.addView(Button(this).apply {
            text = "Сохранить CDN Fronting"
            setOnClickListener {
                val port = etCdnPort.text.toString().toIntOrNull() ?: 443
                ApfCore.setCDNConfig(etCdnWorker.text.toString(), etCdnHost.text.toString(), port)
                toast(getString(R.string.t_cdn_saved))
            }
        })

        AlertDialog.Builder(this)
            .setTitle("Анти-DPI / Скрытность")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    /**
     * Э-UI-6 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.6). internal/antiblock и
     * internal/residential на бэкенде полностью работают и открыты на десктопе —
     * на Android не было ни моста, ни экрана. Проверка IP текущего узла
     * блокирует поток (до 10с) — тот же приём Thread + runOnUiThread, что и в
     * showPrivacyDialog/showDpiDialog. Точная форма ответа CheckCurrentIP не
     * задокументирована как публичный контракт (внутренняя структура
     * internal/residential) — результат просто показывается как отформатированный
     * JSON, а не разбирается по конкретным полям, которые могли бы разойтись
     * молча.
     */
    private fun showAntiBlockDialog() {
        val status = try {
            JSONObject(ApfCore.antiBlockStatusJson())
        } catch (e: Exception) {
            Log.w(TAG, "разбор статуса анти-блокировки: $e")
            JSONObject()
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        fun header(text: String) {
            container.addView(TextView(this).apply {
                this.text = text
                setTextColor(getColor(android.R.color.darker_gray))
                setPadding(0, 24, 0, 8)
            })
        }

        header("Настройки")
        container.addView(infoRow(
            "Анти-блокировка проверяет тип IP-адреса текущего сервера и, если включены " +
                "опции ниже, предпочитает резидентские (не дата-центровые) адреса — " +
                "некоторые сайты (Netflix, банки) блокируют IP дата-центров даже при " +
                "рабочем VPN. Трафик по-прежнему идёт через VPN, меняется только выбор " +
                "адреса, не маршрут."
        ))
        val swEnabled = Switch(this).apply {
            text = "Включена"
            isChecked = status.optBoolean("enabled")
        }
        val swResidential = Switch(this).apply {
            text = "Только резидентские IP"
            isChecked = status.optBoolean("residential_only")
        }
        val swAutoSwitch = Switch(this).apply {
            text = "Автопереключение при датацентре"
            isChecked = status.optBoolean("auto_switch")
        }
        val etApiKey = EditText(this).apply { hint = "API-ключ проверки IP (опционально)" }
        val applyConfig = {
            ApfCore.setAntiBlockConfig(
                swEnabled.isChecked, swResidential.isChecked, swAutoSwitch.isChecked,
                etApiKey.text.toString()
            )
        }
        swEnabled.setOnCheckedChangeListener { _, _ -> applyConfig() }
        swResidential.setOnCheckedChangeListener { _, _ -> applyConfig() }
        swAutoSwitch.setOnCheckedChangeListener { _, _ -> applyConfig() }
        container.addView(swEnabled)
        container.addView(swResidential)
        container.addView(swAutoSwitch)
        container.addView(etApiKey)
        container.addView(Button(this).apply {
            text = "Сохранить API-ключ"
            setOnClickListener { applyConfig(); toast(getString(R.string.t_saved)) }
        })

        header("Проверка IP текущего узла")
        val tvIpResult = TextView(this).apply {
            text = "Нажмите «Проверить», чтобы узнать тип IP активного узла (до 10 секунд)"
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 0, 0, 12)
        }
        container.addView(tvIpResult)
        val btnCheckIp = Button(this).apply { text = "Проверить IP" }
        btnCheckIp.setOnClickListener {
            btnCheckIp.isEnabled = false
            tvIpResult.text = "Проверка идёт…"
            Thread {
                val resultJson = ApfCore.checkCurrentIPJson()
                runOnUiThread {
                    btnCheckIp.isEnabled = true
                    tvIpResult.text = try {
                        val r = JSONObject(resultJson)
                        if (r.has("error")) "Ошибка: ${r.optString("error")}" else r.toString(2)
                    } catch (e: Exception) {
                        "Не удалось разобрать результат: $e"
                    }
                }
            }.start()
        }
        container.addView(btnCheckIp)

        // Найдено 2026-08-13 (см. docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §2): "bypass" тут -
        // это ДВЕ разных вещи под одним списком. requireResidential (переключатель выше в
        // строке) - домен ВСЁ РАВНО идёт через VPN, но предпочтителен residential-узел
        // (анти-VPN-блок площадок вроде Netflix/банков). direct_route - домен идёт
        // НАПРЯМУЮ, В ОБХОД VPN целиком (реальный сплит-туннелинг, config_builder.
        // SetBypassDomains) - трафик по нему НЕ защищён VPN. Раньше direct_route не
        // существовало вообще: список был, а маршрутизация его не видела.
        var currentDialog: AlertDialog? = null
        val rules = try {
            JSONArray(ApfCore.bypassRulesJson())
        } catch (e: Exception) {
            JSONArray()
        }

        // Живая просьба пользователя 2026-08-25: один сплошной список (стриминг +
        // российские сервисы + свои правила) было тяжело просматривать — «мои правила»
        // терялись среди десятка встроенных. Группировка чисто на стороне Kotlin по
        // известным ID встроенных правил (internal/bypass/rules.go) — не требует менять
        // JSON-схему/Go-слой, id встроенных правил стабильны (это ключи для
        // ApfCore.setBypassRule).
        val streamingIds = setOf("netflix", "disneyplus", "hulu", "hbomax", "amazonprime", "spotify", "steam")
        val ruIds = setOf("gosuslugi", "sberbank", "tinkoff")
        val aiIds = setOf("chatgpt")

        fun renderRule(rule: JSONObject) {
            val id = rule.optString("id")
            val isBuiltin = rule.optBoolean("builtin")
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(0, 12, 0, 0)
            }
            row.addView(TextView(this).apply {
                text = rule.optString("name", id) +
                    (if (isBuiltin) " (встроенное)" else "") +
                    (if (rule.optBoolean("direct_route")) " · мимо VPN" else "")
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(Switch(this).apply {
                isChecked = rule.optBoolean("enabled")
                setOnCheckedChangeListener { view, checked ->
                    val err = ApfCore.setBypassRule(id, checked)
                    if (err.isNotEmpty()) {
                        // C-17: ни английского префикса «Bypass:», ни сырого ответа моста —
                        // осмысленный русский заголовок по контексту + переведённая причина.
                        showErrorMessage(getString(R.string.e_bypass_toggle, bridgeErrorText(err)))
                        view.setOnCheckedChangeListener(null)
                        view.isChecked = !checked
                    }
                }
            })
            if (!isBuiltin) {
                // U-4: иконки получили подписи — «✎»/«✕» в ряду с тумблером не читались как
                // действия над правилом.
                row.addView(Button(this).apply {
                    text = "✎ Правка"
                    contentDescription = "Изменить правило обхода"
                    setOnClickListener {
                        showEditBypassRuleDialog(rule) {
                            currentDialog?.dismiss()
                            showAntiBlockDialog()
                        }
                    }
                })
                row.addView(Button(this).apply {
                    text = "✕ Удалить"
                    contentDescription = "Удалить правило обхода"
                    setOnClickListener {
                        val err = ApfCore.removeBypassDomain(id)
                        if (err.isNotEmpty()) {
                            showErrorMessage(getString(R.string.e_bypass_remove, bridgeErrorText(err)))
                        } else {
                            toast(getString(R.string.t_bypass_removed, rule.optString("name", id)))
                            currentDialog?.dismiss()
                            showAntiBlockDialog()
                        }
                    }
                })
            }
            container.addView(row)
        }

        val allRules = (0 until rules.length()).mapNotNull { rules.optJSONObject(it) }
        val buckets = listOf(
            "Стриминг" to allRules.filter { streamingIds.contains(it.optString("id")) },
            "Российские сервисы (обход VPN)" to allRules.filter { ruIds.contains(it.optString("id")) },
            "ИИ-сервисы" to allRules.filter { aiIds.contains(it.optString("id")) },
            "Мои правила" to allRules.filter { !it.optBoolean("builtin") }
        )
        for ((title, bucketRules) in buckets) {
            if (bucketRules.isEmpty()) continue
            header(title)
            bucketRules.forEach { renderRule(it) }
        }
        if (rules.length() == 0) {
            // C-17 (UI_CONTRACT §1.3 п.11): слово «bypass» в пользовательском тексте
            // заменено на «правила обхода» — это не подсказка, а замена самого текста.
            header("Правила обхода")
            container.addView(TextView(this).apply {
                text = "Список правил обхода пуст"
                setTextColor(getColor(android.R.color.darker_gray))
            })
        }

        header("Добавить домен в правила обхода")
        container.addView(infoRow(
            "«Резидентский IP» — домен всё равно идёт ЧЕРЕЗ VPN, просто APF выбирает для " +
                "него более «домашний» адрес, а не дата-центровый. «Прямой маршрут» — домен " +
                "идёт МИМО VPN целиком, напрямую в интернет: реальный IP и провайдер видны " +
                "для этого сайта. Используйте прямой маршрут только для сайтов, которые " +
                "ломаются через VPN и не содержат для вас чувствительных данных."
        ))
        val etDomain = EditText(this).apply { hint = "netflix.com" }
        val etName = EditText(this).apply { hint = "Название, например Netflix" }
        val swDomainResidential = Switch(this).apply {
            text = "Требовать резидентский IP (идёт через VPN)"
        }
        val swDomainDirect = Switch(this).apply {
            text = "Прямой маршрут — идёт МИМО VPN (не защищено!)"
        }
        container.addView(etDomain)
        container.addView(etName)
        container.addView(swDomainResidential)
        container.addView(swDomainDirect)
        container.addView(Button(this).apply {
            text = "Добавить"
            setOnClickListener {
                val domain = etDomain.text.toString().trim()
                if (domain.isEmpty()) {
                    toast(getString(R.string.t_bypass_need_domain))
                    return@setOnClickListener
                }
                // C-17 / UI_CONTRACT §7.3 (живой прогон C4): ввод «http://» давал
                // `Bypass: failed to add` — по-английски и без причины. Самый частый вид
                // мусорного ввода распознаётся здесь же, ДО обращения к мосту, и объясняется
                // конкретно: «уберите http://», а не общее «ошибка».
                if (domain.contains("://") || domain.contains("/")) {
                    showErrorMessage(
                        getString(R.string.e_bypass_add, getString(R.string.err_invalid_domain))
                    )
                    return@setOnClickListener
                }
                val err = ApfCore.addBypassDomain(
                    domain, etName.text.toString().trim(),
                    swDomainResidential.isChecked, swDomainDirect.isChecked
                )
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_bypass_add, bridgeErrorText(err)))
                } else {
                    toast(getString(R.string.t_bypass_added, domain))
                    currentDialog?.dismiss()
                    showAntiBlockDialog()
                }
            }
        })

        header("Приложения вне VPN")
        container.addView(infoRow(
            "Отдельный механизм, сильнее байпаса по домену. Байпас отправляет трафик мимо " +
                "туннеля, но система всё равно сообщает приложению, что VPN активен — и " +
                "сервисы, которые отказываются работать при любых признаках VPN или прокси " +
                "(госуслуги, банки, платёжные сервисы, маркетплейсы), всё равно блокируют вход. " +
                "Приложение из этого списка исключается из VPN полностью: для него сеть " +
                "выглядит так, будто VPN не запущен. Его трафик идёт напрямую с вашим " +
                "настоящим IP."
        ))
        container.addView(Button(this).apply {
            text = "Выбрать приложения"
            setOnClickListener {
                currentDialog?.dismiss()
                showDisallowedAppsDialog()
            }
        })
        val excludedNow = try {
            JSONArray(ApfCore.disallowedAppsJson()).length()
        } catch (e: Exception) {
            0
        }
        container.addView(TextView(this).apply {
            text = if (excludedNow == 0) {
                "Сейчас: ни одно приложение не исключено"
            } else {
                "Сейчас исключено приложений: $excludedNow"
            }
            setTextColor(getColor(android.R.color.darker_gray))
            setPadding(0, 8, 0, 0)
        })

        currentDialog = AlertDialog.Builder(this)
            .setTitle("Анти-блокировка")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    /**
     * Экран выбора приложений, которые не заворачиваются в VPN
     * (VpnService.Builder.addDisallowedApplication, см. APFVpnService.applyDisallowedApps).
     *
     * Список пользовательский и общий: заранее перечислить сервисы, которые блокируют работу
     * при признаках VPN/прокси, невозможно — у каждого свой набор, и он меняется чаще, чем
     * выходят сборки. Поэтому здесь все установленные приложения с поиском, а не готовый
     * список «Госуслуги/Сбер».
     *
     * Перечисление пакетов делается в фоновом потоке: getInstalledApplications + загрузка
     * подписи каждого приложения на телефоне с сотнями пакетов занимает заметное время, и на
     * главном потоке это выглядело бы как зависший интерфейс.
     */
    private fun showDisallowedAppsDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        container.addView(infoRow(
            "Отмеченные приложения работают в обход VPN — с вашим настоящим IP. " +
                "Для них сеть выглядит так, будто VPN не запущен.\n\n" +
                "Честное ограничение: это снимает главный признак — «на сети активен VPN», " +
                "по которому проверяет подавляющее большинство приложений. Но полностью " +
                "скрыть VPN на Android без root нельзя: сетевой интерфейс туннеля и сам факт " +
                "установленного APF остаются видимыми, если приложение проверяет и их."
        ))
        val loading = TextView(this).apply {
            text = "Читаю список установленных приложений…"
            setTextColor(getColor(android.R.color.darker_gray))
        }
        container.addView(loading)

        val listHolder = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val etSearch = EditText(this).apply {
            hint = "Поиск по названию"
            isVisible = false
        }
        container.addView(etSearch)
        container.addView(listHolder)

        val dialog = AlertDialog.Builder(this)
            .setTitle("Приложения вне VPN")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Готово", null)
            .setNegativeButton("Назад") { _, _ -> showAntiBlockDialog() }
            .show()

        // Найдено консилиумом 2026-08-24: тело потока раньше не было защищено try/catch.
        // getInstalledApplications/getLaunchIntentForPackage/getApplicationLabel — реальные
        // системные вызовы (в отличие от остальных фоновых потоков в этом файле, которые
        // зовут только Go-мост, возвращающий ошибки строкой, не исключением), и на части
        // OEM-прошивок или при перезапуске system_server способны бросить необработанное
        // исключение. APFVpnService живёт в том же процессе (нет android:process в манифесте),
        // поэтому непойманное исключение в этом потоке убивало бы процесс ВМЕСТЕ с активным
        // VPN-туннелем — тот самый случай, когда попытка посмотреть список приложений роняла
        // бы уже работающее подключение.
        Thread {
            try {
                val pm = packageManager
                val selected = try {
                    val arr = JSONArray(ApfCore.disallowedAppsJson())
                    (0 until arr.length()).mapNotNull { arr.optString(it, null) }.toMutableSet()
                } catch (e: Exception) {
                    mutableSetOf<String>()
                }

                // Только приложения, у которых есть значок запуска: системные службы без
                // интерфейса пользователю выбирать незачем, а их в списке большинство.
                val launchable = pm.getInstalledApplications(0)
                    .filter { it.packageName != packageName && pm.getLaunchIntentForPackage(it.packageName) != null }
                    .map { it.packageName to pm.getApplicationLabel(it).toString() }
                    .sortedBy { it.second.lowercase() }

                runOnUiThread {
                    if (isFinishing) return@runOnUiThread
                    loading.isVisible = false
                    etSearch.isVisible = true

                    fun render(filter: String) {
                        listHolder.removeAllViews()
                        val needle = filter.trim().lowercase()
                        val shown = launchable.filter {
                            needle.isEmpty() || it.second.lowercase().contains(needle) ||
                                it.first.lowercase().contains(needle)
                        }
                        if (shown.isEmpty()) {
                            listHolder.addView(TextView(this).apply {
                                text = "Ничего не найдено"
                                setTextColor(getColor(android.R.color.darker_gray))
                            })
                            return
                        }
                        for ((pkg, label) in shown.take(300)) {
                            listHolder.addView(Switch(this).apply {
                                text = label
                                isChecked = selected.contains(pkg)
                                setOnCheckedChangeListener { _, checked ->
                                    if (checked) selected.add(pkg) else selected.remove(pkg)
                                    val err = ApfCore.setDisallowedApps(selected.toList())
                                    if (err.isNotEmpty()) {
                                showErrorMessage(
                                    getString(R.string.e_disallowed_apps, bridgeErrorText(err))
                                )
                            }
                                    updateDisallowedAppsIndicator()
                                }
                            })
                        }
                        if (shown.size > 300) {
                            listHolder.addView(TextView(this).apply {
                                text = "Показаны первые 300 из ${shown.size} — уточните поиск"
                                setTextColor(getColor(android.R.color.darker_gray))
                            })
                        }
                    }

                    render("")
                    etSearch.addTextChangedListener(object : android.text.TextWatcher {
                        override fun afterTextChanged(s: android.text.Editable?) = render(s?.toString() ?: "")
                        override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                        override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                    })

                    container.addView(TextView(this).apply {
                        text = "Изменения применяются при следующем подключении. " +
                            "Если VPN уже запущен — переподключитесь."
                        setTextColor(getColor(android.R.color.holo_orange_light))
                        setPadding(0, 16, 0, 0)
                    })
                }
            } catch (e: Throwable) {
                Log.e(TAG, "showDisallowedAppsDialog: $e")
                runOnUiThread {
                    if (isFinishing) return@runOnUiThread
                    loading.isVisible = false
                    loading.text = "Не удалось прочитать список приложений: ${e.message}"
                    loading.setTextColor(getColor(android.R.color.holo_red_light))
                }
            }
        }.start()

        // Держим ссылку, чтобы диалог не считался неиспользуемым и закрывался предсказуемо.
        dialog.setOnDismissListener { }
    }

    /** Диалог редактирования уже существующего пользовательского bypass-правила (не
     * встроенного). onDone зовётся после успешного сохранения — родитель перерисовывает
     * список свежими данными (см. showAntiBlockDialog). */
    private fun showEditBypassRuleDialog(rule: JSONObject, onDone: () -> Unit) {
        val id = rule.optString("id")
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        val currentDomain = rule.optJSONArray("domains")?.optString(0, "") ?: ""
        val etDomain = EditText(this).apply { hint = "домен"; setText(currentDomain) }
        val etName = EditText(this).apply { hint = "название"; setText(rule.optString("name")) }
        val swResidential = Switch(this).apply {
            text = "Требовать резидентский IP (идёт через VPN)"
            isChecked = rule.optBoolean("require_residential")
        }
        val swDirect = Switch(this).apply {
            text = "Прямой маршрут — идёт МИМО VPN (не защищено!)"
            isChecked = rule.optBoolean("direct_route")
        }
        container.addView(etDomain)
        container.addView(etName)
        container.addView(infoRow(
            "«Резидентский IP» — домен всё равно идёт ЧЕРЕЗ VPN, просто APF выбирает для " +
                "него более «домашний» адрес, а не дата-центровый. «Прямой маршрут» — домен " +
                "идёт МИМО VPN целиком, напрямую в интернет: реальный IP и провайдер видны " +
                "для этого сайта."
        ))
        container.addView(swResidential)
        container.addView(swDirect)

        AlertDialog.Builder(this)
            .setTitle("Редактировать правило")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Сохранить") { _, _ ->
                val err = ApfCore.updateBypassDomain(
                    id, etDomain.text.toString().trim(), etName.text.toString().trim(),
                    swResidential.isChecked, swDirect.isChecked
                )
                if (err.isNotEmpty()) {
                    showErrorMessage(getString(R.string.e_bypass_update, bridgeErrorText(err)))
                } else {
                    toast(getString(R.string.t_saved))
                    onDone()
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    /**
     * Э-UI-7 (docs/TZ_ANDROID_UI_PARITY_v1.0.md §1.7, последний этап паритета).
     * internal/crypto и internal/emergency на бэкенде полностью работают и
     * открыты на десктопе — на Android не было ни моста, ни экрана.
     *
     * Аварийная очистка НЕОБРАТИМА (удаляет кэш узлов/конфиг/логи и обрывает
     * текущий сеанс движка) — два независимых слоя подтверждения: поле, где
     * нужно набрать буквально «WIPE» (тот же протокол, что уже проверяет сам
     * мост, EmergencyWipeJSON — не только UI-decorация), и стандартный
     * системный диалог "да/нет" поверх него. Ни разу не нажималась на живом
     * устройстве в рамках приёмки этого этапа — необратимое действие с кэшем
     * в 5000+ узлов на тестовом телефоне сознательно не проверялось живьём,
     * только отказ на неверном confirm (см. TestEmergencyWipe_
     * RequiresExactConfirmString в mobile/androidbridge/bridge_test.go).
     */
    private fun showEmergencyDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        fun header(text: String) {
            container.addView(TextView(this).apply {
                this.text = text
                setTextColor(getColor(android.R.color.darker_gray))
                setPadding(0, 24, 0, 8)
            })
        }

        header("Шифрование кэша узлов (AES-256-GCM)")
        container.addView(infoRow(
            "Шифрует сохранённый на телефоне список серверов мастер-паролем — без него " +
                "файл кэша нельзя прочитать, даже имея доступ к памяти устройства. Пароль " +
                "нигде не сохраняется — если забыть его, кэш узлов станет недоступен и его " +
                "придётся собрать заново (список серверов не пропадёт целиком, просто APF " +
                "не сможет прочитать сохранённые метрики)."
        ))
        val etPassword = EditText(this).apply {
            hint = "Мастер-пароль"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        container.addView(etPassword)
        container.addView(Button(this).apply {
            text = "Включить шифрование"
            setOnClickListener {
                val pw = etPassword.text.toString()
                if (pw.isEmpty()) {
                    toast(getString(R.string.t_need_password))
                    return@setOnClickListener
                }
                ApfCore.setMasterPassword(pw)
                toast(getString(R.string.t_crypto_on))
            }
        })
        container.addView(Button(this).apply {
            text = "Выключить шифрование"
            setOnClickListener {
                // K2-A (E2 #11, свод C трек 1 п.14): третье действие того же класса —
                // снятие защиты одним тапом. Включение шифрования подтверждения не
                // требует (оно защищает), выключение — требует: после него список
                // серверов и метрики лежат на телефоне открытым текстом.
                confirmDisableProtection(
                    title = "Выключить шифрование кэша?",
                    message = "Список серверов и метрики перестанут быть зашифрованными " +
                        "мастер-паролем — их сможет прочитать любой, у кого есть доступ к " +
                        "памяти устройства.",
                    onConfirm = {
                        ApfCore.setMasterPassword("")
                        etPassword.text.clear()
                        toast(getString(R.string.t_crypto_off))
                    },
                    onCancel = {}
                )
            }
        })

        header("Аварийная очистка")
        container.addView(TextView(this).apply {
            text = "Необратимо удаляет кэш узлов, конфигурацию и логи APF. " +
                "Активное подключение будет прервано."
            setTextColor(getColor(android.R.color.holo_red_light))
            setPadding(0, 0, 0, 12)
        })
        val swWipeAll = Switch(this).apply {
            text = "Также удалить sing-box (потребует переустановки)"
        }
        container.addView(swWipeAll)
        val etConfirm = EditText(this).apply { hint = "Наберите WIPE для подтверждения" }
        container.addView(etConfirm)
        // U-16 (UI_CONTRACT §1.1, строка 4): единое имя действия на трёх интерфейсах.
        // Заголовок раздела («Аварийная очистка») — рубрика, его унификация не требуется.
        val btnWipe = Button(this).apply {
            text = "Экстренно стереть все данные"
            setTextColor(getColor(android.R.color.holo_red_light))
        }
        btnWipe.setOnClickListener {
            val confirm = etConfirm.text.toString()
            if (confirm != "WIPE") {
                toast(getString(R.string.t_wipe_need_confirm))
                return@setOnClickListener
            }
            AlertDialog.Builder(this)
                .setTitle("Точно стереть данные?")
                .setMessage("Действие необратимо. APF нужно будет настроить заново.")
                .setPositiveButton("Стереть") { _, _ ->
                    btnWipe.isEnabled = false
                    Thread {
                        val resultJson = ApfCore.emergencyWipeJson(swWipeAll.isChecked, confirm)
                        runOnUiThread {
                            try {
                                val r = JSONObject(resultJson)
                                if (r.has("error")) {
                                    showErrorMessage(
                                        getString(R.string.e_wipe, bridgeErrorText(r.optString("error")))
                                    )
                                    btnWipe.isEnabled = true
                                } else {
                                    toast(getString(R.string.t_wipe_done, r.optInt("files_deleted")))
                                }
                            } catch (e: Exception) {
                                showErrorMessage(getString(R.string.e_parse_result, e.toString()))
                                btnWipe.isEnabled = true
                            }
                        }
                    }.start()
                }
                .setNegativeButton("Отмена", null)
                .show()
        }
        container.addView(btnWipe)

        AlertDialog.Builder(this)
            .setTitle("Аварийная очистка")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    /**
     * Э-UI-1: ApfCore.diagnosticsJson уже был в мосте — экрана/диалога для него не было.
     * Простой AlertDialog, а не отдельный экран — соразмерно объёму данных (плоский JSON
     * из GetDiagnostics, internal/engine/engine.go) и духу "самой дешёвой правки" из ТЗ.
     */
    private fun showDiagnosticsDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }

        // U-6 (E2 #13, живой B9): раньше единственным ответом на вопрос «почему не работает»
        // был плоский дамп GetDiagnostics — двенадцать технических строк, из которых
        // пользователь не мог сделать ни одного вывода. Теперь сверху 3-5 строк человеческим
        // языком, а дамп уехал под свёртку «Технические подробности» (он не удалён: именно
        // по нему разбираются сбои, когда пользователь присылает скриншот).
        container.addView(TextView(this).apply {
            text = diagnosticsSummary()
            setTextColor(getColor(android.R.color.white))
            setPadding(0, 0, 0, 12)
        })

        // U-17 (C-4): отказ записи узлов на диск — здесь же, отдельной оранжевой строкой.
        persistWarningText()?.let { warn ->
            container.addView(TextView(this).apply {
                text = warn
                setTextColor(0xFFF5A623.toInt())
                textSize = 12f
                setPadding(0, 0, 0, 12)
            })
        }

        // Имя НЕ `text`: ниже значение присваивается внутри TextView.apply { }, где `text` —
        // ещё и свойство самого TextView, и читать такой код пришлось бы с оглядкой на
        // правила разрешения имён.
        val rawDump = try {
            val d = JSONObject(ApfCore.diagnosticsJson())
            buildString {
                appendLine("Версия APF: ${d.optString("apf_version", "?")}")
                appendLine("Версия sing-box: ${d.optString("sing_box_version", "?")}")
                // U-5 (словарь UI_CONTRACT §1.3, п.3-7): голые технические имена заменены
                // человеческими подписями — «SOCKS порт», «Тип блокировки», «Стратегия»,
                // «Reality», «CDN» ничего не говорили тому, кто не читал исходники.
                appendLine("Локальный порт прокси: ${ApfCore.socksPort()}")
                appendLine()
                // K2-A (свод C трек 1 п.10, B3 #5): строка «Состояние FSM» снята.
                // Консилиум B3 установил, что протокольная таблица TunnelFSM мертва —
                // движок выбирает резерв живой иерархией tryFallback (engine.go:4026-4096)
                // и с состоянием этой машины не сверяется. То есть экран диагностики
                // показывал значение, которое не описывает ни одно реальное решение
                // движка, — а диагностика, которая врёт, хуже отсутствующей: по ней
                // строят гипотезу о причине сбоя. Поле остаётся в GetDiagnosticsJSON
                // (его читают тесты и, при необходимости, лог) — убрана только
                // публикация на пользовательский экран.
                appendLine("Тип блокировки (определено провайдером): ${d.optString("blockage_type", "?")}")
                appendLine("Стратегия обхода: ${d.optString("strategy_primary", "?")}")
                appendLine("Причина: ${d.optString("strategy_reason", "?")}")
                appendLine("Reality (маскировка под HTTPS): ${d.optBoolean("use_reality")}")
                appendLine("Через CDN: ${d.optBoolean("use_cdn")}")
                appendLine("Цепочка: ${d.optBoolean("use_chain")}")
                appendLine()
                appendLine("IPv6 Block: ${d.optBoolean("ipv6_block")}")
                appendLine("WebRTC Guard: ${d.optBoolean("webrtc_block")}")
                appendLine("Шифрование хранилища: ${d.optBoolean("crypto_enabled")}")
                val rb = d.optJSONObject("last_rollback")
                if (rb != null) {
                    appendLine()
                    appendLine("Последний откат: ${rb.optString("stage", "?")} — ${rb.optString("reason", "?")}")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "разбор диагностики: $e")
            "Не удалось прочитать диагностику: $e"
        }

        val tvRaw = TextView(this).apply {
            this.text = rawDump
            setTextColor(getColor(android.R.color.darker_gray))
            textSize = 12f
            isVisible = false
        }
        container.addView(Button(this).apply {
            this.text = "Технические подробности"
            setOnClickListener { tvRaw.isVisible = !tvRaw.isVisible }
        })
        container.addView(tvRaw)

        // U-4 (E2 §2): «Выгрузить лог» стояла нейтральной кнопкой Material-диалога — слева,
        // тем же серым, что и «Отмена», и читалась как отказ от действия. Это положительное
        // действие, поэтому теперь оно и стоит на положительной кнопке, а «Закрыть» —
        // на отрицательной.
        AlertDialog.Builder(this)
            .setTitle("Диагностика")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton(getString(R.string.btn_export_log)) { _, _ -> exportLogFile() }
            .setNegativeButton(getString(R.string.btn_close), null)
            .show()
    }

    /**
     * U-6: 3-5 строк человеческим языком поверх технического дампа.
     *
     * Отвечает ровно на тот вопрос, ради которого этот экран открывают: «работает ли сейчас
     * и почему нет». Источники — те же, что у главного экрана (служба + мост), новых полей
     * не заводится.
     */
    private fun diagnosticsSummary(): String = buildString {
        val service = vpnService
        val state = service?.getState()?.name ?: "IDLE"
        val verify = service?.getVerifyState() ?: VERIFY_IDLE
        appendLine(
            when {
                state == "IDLE" -> "APF отключён — туннеля нет, трафик идёт обычным путём."
                state == "CONNECTING" -> "Идёт подбор сервера. Туннеля ещё нет."
                verify == VERIFY_VERIFIED ->
                    "Туннель поднят, трафик через него проверен — соединение работает."
                verify == VERIFY_FAILED ->
                    "Туннель поднят, но трафик через него не идёт. Помогает «⇄ Сменить сервер»."
                verify == VERIFY_CHECKING ->
                    "Туннель поднят, идёт проверка: пропускает ли выбранный сервер трафик."
                state == "ERROR" -> "Последняя попытка подключения не удалась."
                else -> "Состояние подключения уточняется."
            }
        )
        val node = service?.getNodeName().orEmpty()
        if (node.isNotEmpty()) appendLine("Сервер: $node")
        exitCountryLine()?.let { appendLine(it) }
        appendLine(poolCountsLine())
        val mode = when (service?.getMode()) {
            APFVpnService.Mode.VPN -> "VPN (системный туннель, через него идут все приложения)"
            APFVpnService.Mode.PROXY -> "Прокси (локальный SOCKS5, приложения настраиваются вручную)"
            else -> "не выбран (нет активного подключения)"
        }
        append("Режим: $mode")
    }

    /**
     * Отдаёт файл ApfFileLogger через системный выбор приложения (почта/мессенджер) —
     * просьба пользователя 2026-08-18: обычный пользователь без adb должен суметь прислать
     * разработчику один файл с историей действий/сбоев/поведения движка за последние
     * (до) 72 часов. FileProvider и его пути уже объявлены в манифесте/file_paths.xml.
     */
    private fun exportLogFile() {
        val file = ApfFileLogger.file()
        if (file == null || !file.exists()) {
            toast(getString(R.string.t_log_missing))
            return
        }
        try {
            val uri = androidx.core.content.FileProvider.getUriForFile(
                this, "$packageName.fileprovider", file
            )
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Отправить лог APF"))
        } catch (e: Exception) {
            Log.e(TAG, "exportLogFile: $e")
            showErrorMessage(getString(R.string.e_log_export, e.toString()))
        }
    }

    /**
     * Переключатель Kill Switch (дефект D-A24).
     *
     * Ядро может ОТКЛОНИТЬ требование: на Android защиту включает только система
     * («Always-on VPN» + «Блокировать соединения без VPN»), а пока её нет, требование
     * не добавляет защиты, но заставляет движок откатывать каждое подключение.
     *
     * При отказе переключатель возвращается в прежнее положение: он обязан показывать
     * состояние ядра, а не намерение пользователя. На время возврата слушатель снимается,
     * иначе программное изменение вызвало бы его повторно.
     */
    // Именно метод, а не свойство-лямбда: при восстановлении переключателя слушатель
    // навешивает сам себя, а свойство ссылаться на себя в инициализаторе не может
    // («Variable must be initialized»). Ссылка на метод (::) этой трудности не создаёт.
    private fun onKillSwitchToggled(view: CompoundButton, checked: Boolean) {
        // K2-A (E2 #11, свод C трек 1 п.14): снятие защиты спрашивает подтверждение,
        // включение — нет. Включение уже было безопасным действием и остаётся таким.
        if (!checked) {
            confirmDisableProtection(
                title = "Выключить Kill Switch?",
                message = "Kill Switch блокирует интернет, если VPN-туннель обрывается. " +
                    "Без него при разрыве связи трафик пойдёт напрямую, с вашим настоящим " +
                    "IP-адресом, и приложения этого не покажут.",
                onConfirm = { applyKillSwitch(view, false) },
                onCancel = { restoreKillSwitch(view, true) }
            )
            return
        }
        applyKillSwitch(view, true)
    }

    private fun applyKillSwitch(view: CompoundButton, enabled: Boolean) {
        val error = ApfCore.setKillSwitch(enabled)
        if (error.isEmpty()) return
        // C-17 / UI_CONTRACT §6.3 (живой прогон, «Найденное сверх ожиданий» п.5): отказ
        // SetKillSwitch — три предложения (~230 символов), и системный toast обрезал их на
        // реальном устройстве (MIUI ограничивает высоту всплывающего окна). Длительность
        // тут ни при чём — уже стояла LENGTH_LONG. Длинные сообщения об ошибке показываются
        // диалогом, из которого текст виден целиком (см. showErrorMessage).
        showErrorMessage(bridgeErrorText(error), getString(R.string.e_killswitch_title))
        restoreKillSwitch(view, !enabled)
    }

    private fun restoreKillSwitch(view: CompoundButton, checked: Boolean) {
        view.setOnCheckedChangeListener(null)
        view.isChecked = checked
        view.setOnCheckedChangeListener(::onKillSwitchToggled)
    }

    /**
     * K2-A: тумблер IPv6 Block.
     *
     * Было (D1 §2.4, E2 таблица §4): анонимный слушатель, который применял значение сразу
     * и при отказе ядра НЕ откатывал переключатель — экран оставался с положением, которого
     * в ядре нет. Стало: выключение подтверждается (п.14), а отказ ядра откатывает тумблер
     * так же, как это давно делает Kill Switch.
     */
    private fun onIpv6BlockToggled(view: CompoundButton, checked: Boolean) {
        if (!checked) {
            confirmDisableProtection(
                title = "Выключить блокировку IPv6?",
                message = "Блокировка не даёт IPv6-трафику уйти мимо туннеля. Если у сети " +
                    "телефона есть рабочий IPv6, без неё часть трафика пойдёт напрямую и " +
                    "раскроет ваше настоящее местоположение.",
                onConfirm = { applyIpv6Block(view, false) },
                onCancel = { restoreIpv6Switch(view, true) }
            )
            return
        }
        applyIpv6Block(view, true)
    }

    private fun applyIpv6Block(view: CompoundButton, enabled: Boolean) {
        val err = ApfCore.setIPv6Block(enabled)
        if (err.isEmpty()) return
        showErrorMessage(getString(R.string.e_ipv6, bridgeErrorText(err)))
        restoreIpv6Switch(view, !enabled)
    }

    private fun bindVpnService() {
        bindService(
            Intent(this, APFVpnService::class.java),
            serviceConnection,
            Context.BIND_AUTO_CREATE
        )
    }

    // ─── Действия ─────────────────────────────────────────────────────────────

    private fun onConnectClick() {
        val service = vpnService
        val st = service?.getState()?.name
        // ТЗ v1.3 F6: «Отмена» во время подключения/проверки канала — тот же путь, что и
        // отключение (служба сама отменяет незавершённую попытку: cancelConnectAttempt).
        // isSessionActive(), а не isConnected() (D9): кнопка обязана отключать и
        // неподтверждённый туннель — иначе на нём она превратилась бы в «Подключить»
        // поверх живого сеанса.
        if (service != null && (service.isSessionActive() || st == "CONNECTING" || st == "VERIFYING")) {
            sendCommand(APFVpnService.ACTION_DISCONNECT)
            return
        }
        // U-18 (E2 #16): «Подключить» ВСЕГДА подключает выбранный узел — непустое поле
        // ссылки больше не меняет смысл кнопки молча и только в режиме VPN. Для вставленной
        // ссылки есть отдельное, названное действие «Добавить и подключиться»
        // (btnAddAndConnect, появляется, когда поле непусто) — одинаково в обоих режимах.
        pendingVpnNodeLink = null
        if (swVpnMode.isChecked) {
            // Режим VPN: сначала согласие системы. prepare() возвращает null, если оно уже
            // есть (например, дано в прошлом сеансе) — тогда просить заново не нужно.
            val consentIntent = VpnService.prepare(this)
            if (consentIntent != null) {
                vpnConsent.launch(consentIntent)
            } else {
                startVpnAfterConsent()
                toast(getString(R.string.t_vpn_starting))
            }
        } else {
            // Режим «прокси»: разрешение VpnService НЕ запрашивается — туннель не создаётся.
            sendCommand(APFVpnService.ACTION_CONNECT_PROXY, foreground = true)
            toast(getString(R.string.t_proxy_scanning))
        }
    }

    /**
     * U-18: «Добавить и подключиться» — то, что раньше делала кнопка «Подключить» при
     * непустом поле ссылки, но теперь названо своим именем и работает в ОБОИХ режимах.
     *
     * Порядок действий тот же, что и был: узел сначала добавляется в пул (иначе после
     * отключения ссылка потеряется), затем поднимается сеанс именно к нему — через службу,
     * а не прямым вызовом ядра (ТЗ v1.3 F6/КТ-14: состояние экрана, уведомление и TUN — у неё).
     */
    private fun onAddAndConnectClick() {
        val link = etNodeLink.text.toString().trim()
        if (link.isEmpty()) {
            toast(getString(R.string.t_need_link))
            return
        }
        if (!link.matches(Regex("^(vless|vmess|ss|trojan|wireguard)://.+"))) {
            toast(getString(R.string.t_bad_link))
            return
        }
        val error = ApfCore.addNode(link)
        if (error.isNotEmpty()) {
            showErrorMessage(getString(R.string.e_add_node, bridgeErrorText(error)))
            return
        }
        etNodeLink.text.clear()
        if (swVpnMode.isChecked) {
            pendingVpnNodeLink = link
            pendingVpnChainPartner = false
            val consentIntent = VpnService.prepare(this)
            if (consentIntent != null) {
                vpnConsent.launch(consentIntent)
            } else {
                startVpnAfterConsent()
                toast(getString(R.string.t_vpn_starting))
            }
        } else {
            startForegroundService(Intent(this, APFVpnService::class.java).apply {
                action = APFVpnService.ACTION_CONNECT_PROXY_TO_NODE
                putExtra(APFVpnService.EXTRA_NODE_LINK, link)
            })
            toast(getString(R.string.t_proxy_scanning))
        }
    }

    /** Общая точка после получения согласия VpnService (сразу, если оно уже было раньше,
     * или из колбэка vpnConsent) — выбирает действие по pendingVpnNodeLink. */
    private fun startVpnAfterConsent() {
        // ТЗ v1.3 F6/КТ-14: узел из «Моих серверов» по ID — через службу.
        val nodeId = pendingVpnNodeId
        pendingVpnNodeId = null
        if (nodeId != null) {
            startForegroundService(Intent(this, APFVpnService::class.java).apply {
                action = APFVpnService.ACTION_CONNECT_VPN_TO_NODE_ID
                putExtra(APFVpnService.EXTRA_NODE_ID, nodeId)
            })
            return
        }
        val link = pendingVpnNodeLink
        pendingVpnNodeLink = null
        val chainPartner = pendingVpnChainPartner
        pendingVpnChainPartner = false
        if (link != null) {
            val intent = Intent(this, APFVpnService::class.java).apply {
                action = APFVpnService.ACTION_CONNECT_VPN_TO_NODE
                putExtra(APFVpnService.EXTRA_NODE_LINK, link)
                putExtra(APFVpnService.EXTRA_CHAIN_PARTNER, chainPartner)
            }
            startForegroundService(intent)
        } else {
            sendCommand(APFVpnService.ACTION_CONNECT_VPN, foreground = true)
        }
    }

    private fun sendCommand(action: String, foreground: Boolean = false) {
        val intent = Intent(this, APFVpnService::class.java).apply { this.action = action }
        if (foreground) startForegroundService(intent) else startService(intent)
    }

    private fun onAddNodeClick() {
        val link = etNodeLink.text.toString().trim()
        if (link.isEmpty()) {
            toast(getString(R.string.t_need_link))
            return
        }
        if (!link.matches(Regex("^(vless|vmess|ss|trojan|wireguard)://.+"))) {
            toast(getString(R.string.t_bad_link))
            return
        }
        val error = ApfCore.addNode(link)
        if (error.isNotEmpty()) {
            showErrorMessage(getString(R.string.e_add_node, bridgeErrorText(error)))
        } else {
            toast(getString(R.string.t_node_added))
            etNodeLink.text.clear()
        }
    }

    /** §4 (docs/PLAN_2026-08-28_stubs_and_realfunc.md) — роль «Вход»: та же ссылка, что и
     * onAddNodeClick, но от партнёра в роли «Выход». В отличие от обычного добавления узла
     * подключается СРАЗУ (не ждёт планового скана) и помечает узел IsChainPartner — при сбое
     * APF будет переподключаться именно к этому партнёру, а не подменит его случайным
     * публичным сервером (Engine.AddChainPartnerFromLink).
     *
     * Живая находка 2026-09-28: раньше здесь был прямой ApfCore.connectChainPartner из
     * активити — мимо APFVpnService. Канал поднимался всегда «прокси» (браузер телефона шёл
     * мимо партнёра даже при включённом режиме VPN), главный экран писал «Отключено» при
     * работающем канале, foreground-службы не было. Теперь — тот же путь службы, что у
     * onAddAndConnectClick, с флагом EXTRA_CHAIN_PARTNER. */
    private fun onConnectChainPartnerClick() {
        val link = etNodeLink.text.toString().trim()
        if (link.isEmpty()) {
            toast(getString(R.string.t_need_partner_link))
            return
        }
        if (!link.matches(Regex("^(vless|vmess|ss|trojan|wireguard)://.+"))) {
            toast(getString(R.string.t_bad_link))
            return
        }
        etNodeLink.text.clear()
        toast(getString(R.string.t_partner_connecting))
        if (swVpnMode.isChecked) {
            pendingVpnNodeLink = link
            pendingVpnChainPartner = true
            val consentIntent = VpnService.prepare(this)
            if (consentIntent != null) {
                vpnConsent.launch(consentIntent)
            } else {
                startVpnAfterConsent()
            }
        } else {
            startForegroundService(Intent(this, APFVpnService::class.java).apply {
                action = APFVpnService.ACTION_CONNECT_PROXY_TO_NODE
                putExtra(APFVpnService.EXTRA_NODE_LINK, link)
                putExtra(APFVpnService.EXTRA_CHAIN_PARTNER, true)
            })
        }
    }

    // ─── Отрисовка ────────────────────────────────────────────────────────────

    private fun updateUI() {
        val service = vpnService ?: return
        // Имя и задержку берём у службы, а не подставляем пустышки: иначе в состоянии
        // CONNECTED экран показывал безличное «сервер выбран» (дефект D-A21).
        renderState(
            state = service.getState().name,
            node = service.getNodeName(),
            latency = service.getLatency(),
            message = service.getMessage(),
            verifyState = service.getVerifyState(),
            verifiedLatency = service.getVerifiedLatency()
        )
        // C-18 (ТЗ v1.4): три ЧЕСТНЫХ числа вместо одного «доступно N из M».
        // «Отвечает по TCP» и «подтверждён трафиком» — разные величины, и живой прогон D7
        // показал разрыв в три порядка: живых 1480 из 5467, подтверждённых трафиком — 2.
        // Одно число «доступно» читалось как «1480 рабочих серверов», чего оно не значит.
        tvStats.text = poolCountsLine() + pinnedLine()
        // U-17 (C-4): движок с фикса K2-E честно проваливает saveNodes при отказе шифрования
        // и НЕ пишет файл — до экрана этот отказ не доезжал вовсе.
        val warn = persistWarningText()
        tvPersistWarn.isVisible = warn != null
        if (warn != null) tvPersistWarn.text = warn
        // C-15/D3: объяснение последнего ручного переключения (пусто ⇒ строка скрыта).
        updateSwitchNotice()
    }

    /**
     * C-18: строка «В пуле N · отвечает по TCP M · подтверждено трафиком K».
     *
     * Числа берутся из GetPoolCountsJSON (мост, лот L1b-ENG2) — их считает движок одним
     * правилом для всех трёх интерфейсов. Прежний getStatsJSON давал только «ok/total», и
     * «ok» означало «порт ответил», а выглядело как «сервер работает».
     */
    private fun poolCountsLine(): String {
        return try {
            val c = JSONObject(ApfCore.poolCountsJson())
            val stale = c.optInt("verify_stale", 0)
            if (stale > 0) {
                getString(
                    R.string.pool_counts_stale,
                    c.optInt("total"), c.optInt("tcp_alive"), c.optInt("proven_traffic"), stale
                )
            } else {
                getString(
                    R.string.pool_counts,
                    c.optInt("total"), c.optInt("tcp_alive"), c.optInt("proven_traffic")
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "разбор счётчиков пула: $e")
            ""
        }
    }

    /**
     * U-17 (C-4, UI_CONTRACT §7.2): текст предупреждения «узлы не сохранены: <причина>» или
     * null, когда всё в порядке.
     *
     * Источник — ДИАГНОСТИКА, а не состояние: поле `last_persist_error` сознательно не
     * добавлено в `models.ConnectionState`/`GetState()` (комментарий движка на этот счёт
     * прямо адресован UI-лотам). Пустая строка ⇒ предупреждение пропадает само после
     * следующей успешной записи, ничего сбрасывать вручную не нужно.
     */
    private fun persistWarningText(): String? {
        return try {
            val err = JSONObject(ApfCore.diagnosticsJson()).optString("last_persist_error", "")
            if (err.isEmpty()) null else getString(R.string.persist_warn, bridgeErrorText(err))
        } catch (e: Exception) {
            null
        }
    }

    // ТЗ v1.3 F2 I3: строка «📌 Закреплён: … (статус)» на главном экране — каждый пропуск
    // закреплённого сервера виден пользователю. Имя ищем в списке только при смене ID.
    private var pinnedNameCacheId: String = ""
    private var pinnedNameCache: String = ""

    private fun pinnedLine(): String {
        return try {
            val st = JSONObject(ApfCore.stateJson())
            val pid = st.optString("pinned_node_id")
            if (pid.isEmpty()) return ""
            if (pid != pinnedNameCacheId) {
                pinnedNameCacheId = pid
                pinnedNameCache = pid.take(10) + "…"
                val nodes = JSONArray(ApfCore.nodesJson())
                for (i in 0 until nodes.length()) {
                    val n = nodes.optJSONObject(i) ?: continue
                    if (n.optString("id") == pid) { pinnedNameCache = n.optString("name", pid); break }
                }
            }
            val status = when (st.optString("pinned_status")) {
                "active" -> "подключён"
                "standby" -> "ожидает выбора"
                "unreachable" -> "пропущен: недоступен/сбой"
                "suppressed" -> "временно пропущен после смены сервера"
                "missing" -> "нет в списке"
                else -> ""
            }
            "\n📌 Закреплён: $pinnedNameCache" + (if (status.isNotEmpty()) " ($status)" else "")
        } catch (e: Exception) {
            ""
        }
    }

    /** Цвет статуса по контракту: verified — зелёный, checking — жёлтый, failed — красный. */
    private fun verifyStateColorRes(verifyState: String): Int = when (verifyState) {
        VERIFY_VERIFIED -> android.R.color.holo_green_light
        VERIFY_CHECKING -> android.R.color.holo_orange_light
        VERIFY_FAILED -> android.R.color.holo_red_light
        else -> android.R.color.darker_gray
    }

    /**
     * Дефект D12. Две задержки — РАЗНЫЕ измерения, и подписывать их одинаковым «мс» нельзя:
     * TCP-рукопожатие до порта проходит и у узла, который не пропускает ни байта полезного
     * трафика (мёртвый Reality-фронт, CDN-edge, отозванный ключ), — именно оно и стояло
     * здесь раньше. Сквозная HTTP-проверка — единственное доказательство того, что канал
     * живой.
     *
     * C-20 (ТЗ v1.4) уточняет вторую половину: сама по себе сквозная проверка НЕ доказывает,
     * что трафик сторонних приложений идёт через системный TUN — почти всегда она сделана
     * через локальный SOCKS5 движка, а в режиме «Прокси» TUN нет вовсе. Поэтому слово
     * «через туннель» ставится только при источнике [VERIFIED_VIA_TUN].
     */
    private fun latencyLabel(tcpLatency: Int, verifiedLatency: Int): String {
        if (verifiedLatency <= 0) {
            return if (tcpLatency > 0) getString(R.string.latency_tcp, tcpLatency) else ""
        }
        // C-20: слово «через туннель» — ТОЛЬКО для TUN-bound замера. Мост говорит, чем
        // именно получена величина (GetActiveNodeVerifiedLatencySource): "tun" — прямая
        // проба мимо SOCKS, тем же путём, что у браузера; "socks5" — через локальный SOCKS
        // движка (в режиме «Прокси» другого и не бывает). Пустой ответ ⇒ источник неизвестен,
        // и тогда берётся нейтральная формулировка, а не оптимистичная.
        return when (ApfCore.activeNodeVerifiedLatencySource()) {
            VERIFIED_VIA_TUN -> getString(R.string.latency_tun, verifiedLatency)
            VERIFIED_VIA_SOCKS -> getString(R.string.latency_socks, verifiedLatency)
            else -> getString(R.string.latency_exit, verifiedLatency)
        }
    }

    /**
     * C-21 (ТЗ v1.4): фактическая страна выхода рядом с меткой каталога, или null.
     *
     * Живой прогон K8-LIVE D1: узел подписан `🇬🇧GB-82.38.31.179-0124`, а фактический выход —
     * `193.29.139.147`, Нидерланды (подтверждено и браузером, и `curl`). То есть выбор
     * «страна выхода», который пользователь делает по метке, ничего не значил.
     *
     * Метка каталога разбирается здесь тем же правилом, что `models.Node.CatalogCountry` на
     * Go-стороне (две заглавные латинские буквы после флаг-эмодзи; три подряд — это слово
     * вроде RELAY, а не код страны). Дублирование правила осознанное: в облегчённый список
     * узлов моста (GetNodesJSON) код страны не попадает, а имя узла — попадает.
     */
    private fun exitCountryLine(): String? {
        val exit = ApfCore.activeNodeExitCountry()
        if (exit.isEmpty()) return null
        val catalog = catalogCountryOf(ApfCore.activeNodeName())
        return when {
            catalog.isEmpty() -> getString(R.string.exit_country_only, exit)
            catalog.equals(exit, ignoreCase = true) ->
                getString(R.string.exit_country_match, catalog.uppercase())
            else -> getString(R.string.exit_country_mismatch, catalog.uppercase(), exit.uppercase())
        }
    }

    /** Двухбуквенный код страны из МЕТКИ узла ("" — метка его не содержит). */
    private fun catalogCountryOf(name: String): String {
        var i = 0
        while (i < name.length && !(name[i] in 'A'..'Z')) i++
        if (i + 1 >= name.length) return ""
        if (name[i + 1] !in 'A'..'Z') return ""
        if (i + 2 < name.length && name[i + 2] in 'A'..'Z') return "" // RELAY/TOR — не страна
        return name.substring(i, i + 2)
    }

    /**
     * КОГДА через сервер в последний раз реально шёл трафик.
     *
     * Раньше мост отдавал в список единственный булев `proven`, и «трафик проходил минуту
     * назад» выглядел на телефоне ровно как «трафик проходил неделю назад» — при том, что
     * выбирать между такими серверами приходится постоянно. Пустая строка (нет ни одного
     * подтверждения) — не пробел в данных: значок в этом случае и так честно говорит, что
     * трафик через сервер не проверялся.
     */
    private fun verifiedAgeLabel(lastVerifiedAtUnix: Long, verifiedCount: Int): String {
        if (lastVerifiedAtUnix <= 0L || verifiedCount <= 0) return ""
        val ageSec = System.currentTimeMillis() / 1000L - lastVerifiedAtUnix
        val ago = when {
            ageSec < 60 -> "только что"
            ageSec < 3600 -> "${ageSec / 60} мин назад"
            ageSec < 86_400 -> "${ageSec / 3600} ч назад"
            else -> "${ageSec / 86_400} сут назад"
        }
        return " · $ago, подтверждений: $verifiedCount"
    }

    /**
     * @param verifyState idle | checking | verified | failed — ЕДИНСТВЕННЫЙ источник статуса
     *        канала (дефект D4).
     *
     * Раньше состояние «канал не подтверждён» вычислялось так:
     *
     *     val unverified = message.contains("не подтверждён")
     *
     * — то есть разбором ПОДСТРОКИ русского текста, который служба собирала для показа
     * пользователю. Любая переформулировка сообщения (перевод, уточнение, опечатка) молча
     * ломала цвет и текст статуса, причём в безопасную для показа сторону: экран возвращался
     * к зелёному «активен» на канале, через который не открывался ни один сайт. Проверка была
     * ещё и одноразовой — состояние ниже по времени не переоценивалось (D6/D7).
     */
    private fun renderState(
        state: String,
        node: String,
        latency: Int,
        message: String,
        verifyState: String,
        verifiedLatency: Int = 0,
    ) {
        // Переключатель режима относится к СЛЕДУЮЩЕМУ подключению, не к текущему сеансу:
        // менять его, пока сеанс жив, значит расходиться с тем, что реально поднято на
        // телефоне (урок D-A31/D-A32 — экран обязан совпадать с фактическим состоянием).
        swVpnMode.isEnabled = state == "IDLE" || state == "ERROR"
        // K2-A (E2 #14, свод C трек 1 п.5): «Сменить сервер» без сеанса ничего не делает —
        // раньше кнопка выглядела доступной и отвечала одним тостом. После LOT-K1 она стоит
        // на первом экране, рядом с «Подключить», то есть жать её будут именно тогда, когда
        // ничего не подключено. Предикат тот же, что и в onForceSwitchClick (isSessionActive),
        // плюс состояния экрана: бродкаст может прийти раньше, чем активити привяжется к
        // службе, и гасить кнопку поверх живого туннеля было бы новой неправдой.
        val sessionLive = vpnService?.isSessionActive() == true ||
            state == "CONNECTED" || state == "VERIFYING"
        btnForceSwitch.isEnabled = sessionLive
        // Тема не гарантирует видимой разницы для кнопки с backgroundTint и своим
        // textColor — приглушаем явно, иначе «выключено» останется незаметным.
        btnForceSwitch.alpha = if (sessionLive) 1.0f else 0.45f
        updateDisallowedAppsIndicator()
        // C-21: вторая метка рисуется УСЛОВНО — пока движок не заполнил фактический выход
        // (или сеанса нет), строка просто скрыта, а не показывает пустоту.
        val exitLine = if (sessionLive) exitCountryLine() else null
        tvExitCountry.isVisible = exitLine != null
        if (exitLine != null) tvExitCountry.text = exitLine
        when (state) {
            "CONNECTING" -> {
                // ТЗ v1.3 F6: кнопка не «мёртвая» — можно отменить (см. onConnectClick).
                // Туннеля ещё нет, поэтому verify_state здесь ни при чём: показывать
                // «Проверяю канал…» до появления канала было бы такой же неправдой.
                btnConnect.text = "Отмена"
                btnConnect.isEnabled = true
                progressBar.isVisible = true
                tvStatus.text = "Подключение"
                tvStatus.setTextColor(getColor(android.R.color.holo_orange_light))
                if (message.isNotEmpty()) tvNodeName.text = message
            }
            "VERIFYING" -> {
                btnConnect.text = "Отмена"
                btnConnect.isEnabled = true
                progressBar.isVisible = true
                // Туннель поднят, идёт сквозная проверка. Если движок уже успел объявить
                // провал — показываем провал, а не бодрое «проверяю».
                val shown = if (verifyState == VERIFY_FAILED) VERIFY_FAILED else VERIFY_CHECKING
                tvStatus.text = verifyStateText(shown)
                tvStatus.setTextColor(getColor(verifyStateColorRes(shown)))
                // Подробности подбора («подбор затянулся — продолжаю перебор серверов»)
                // остаются видны: они полезны, но статусом не являются.
                tvNodeName.text = node.ifEmpty { message.ifEmpty { "ищу рабочий узел" } }
                tvLatency.text = latencyLabel(latency, verifiedLatency)
            }
            "CONNECTED" -> {
                btnConnect.text = "Отключить"
                btnConnect.isEnabled = true
                // Пока канал не подтверждён — работа не окончена, и крутилка об этом честнее
                // статичного экрана.
                progressBar.isVisible = verifyState == VERIFY_CHECKING
                tvStatus.text = verifyStateText(verifyState)
                tvStatus.setTextColor(getColor(verifyStateColorRes(verifyState)))
                val modeLabel = if (vpnService?.getMode() == APFVpnService.Mode.VPN) "VPN" else "Прокси"
                tvNodeName.text = "$modeLabel · ${node.ifEmpty { "сервер выбран" }}"
                tvLatency.text = latencyLabel(latency, verifiedLatency)
            }
            "ERROR" -> {
                btnConnect.text = "Повторить"
                btnConnect.isEnabled = true
                progressBar.isVisible = false
                tvStatus.text = "Ошибка"
                tvStatus.setTextColor(getColor(android.R.color.holo_red_light))
                tvNodeName.text = message.ifEmpty { "нет подключения" }
                tvLatency.text = ""
            }
            else -> {
                btnConnect.text = "Подключить"
                btnConnect.isEnabled = true
                progressBar.isVisible = false
                tvStatus.text = verifyStateText(VERIFY_IDLE)
                tvStatus.setTextColor(getColor(verifyStateColorRes(VERIFY_IDLE)))
                tvNodeName.text = ""
                tvLatency.text = ""
            }
        }
    }

    /**
     * Постоянный индикатор на главном экране: сколько приложений сейчас идут в обход VPN.
     *
     * Найдено консилиумом 2026-08-24: список DisallowedApps персистентный и реально
     * применяется на уровне ОС при каждой сборке TUN (APFVpnService.applyDisallowedApps), но
     * единственное упоминание жило внутри диалога «Приложения вне VPN» — экран CONNECTED
     * показывал только «VPN активен», без единого признака, что часть трафика защищена не
     * полностью. Пользователь, один раз исключивший банк/Госуслуги, месяц спустя в чужой сети
     * увидел бы «VPN активен» и обоснованно доверился бы ему. Вызывается из renderState на
     * каждое обновление состояния — дёшево (короткий JSON от уже инициализированного ядра).
     */
    private fun updateDisallowedAppsIndicator() {
        val count = try {
            JSONArray(ApfCore.disallowedAppsJson()).length()
        } catch (e: Exception) {
            0
        }
        if (count == 0) {
            tvDisallowedAppsIndicator.isVisible = false
            return
        }
        tvDisallowedAppsIndicator.isVisible = true
        tvDisallowedAppsIndicator.text = "⚠ $count прил. идут мимо VPN"
        tvDisallowedAppsIndicator.setOnClickListener { showDisallowedAppsDialog() }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    /**
     * C-17 / UI_CONTRACT §6.3: сообщение об ОШИБКЕ показывается так, чтобы его можно было
     * дочитать.
     *
     * Живой прогон подтвердил: длинный toast (отказ SetKillSwitch — три предложения,
     * ≈230 символов) визуально обрезается прошивкой устройства, хотя код уже использует
     * `Toast.LENGTH_LONG` — то есть проблема не в длительности показа, а в рендеринге.
     * Короткие статусные сообщения («Сервер добавлен») остаются toast'ами: правило касается
     * только сообщений об отказе, которые по своей природе объясняют причину и потому длиннее.
     */
    private fun showErrorMessage(msg: String, title: String? = null) {
        if (title == null && msg.length <= TOAST_MAX_CHARS) {
            toast(msg)
            return
        }
        val builder = AlertDialog.Builder(this).setMessage(msg).setPositiveButton("Понятно", null)
        if (title != null) builder.setTitle(title)
        builder.show()
    }

    /**
     * C-17 (UI_CONTRACT §6.2, §7.1): перевод ответа моста в человеческую фразу.
     *
     * Мост возвращает короткую техническую строку (исторически — по-английски:
     * `"failed to add"`, `"not initialized"`, `"not found or builtin"`), и раньше она
     * уходила пользователю как есть — живой прогон C4 показал toast
     * «Bypass: failed to add» в полностью русском интерфейсе.
     *
     * Функция принимает И будущие коды, которые заведёт лот L1b-ENG2
     * (`invalid_domain` / `duplicate` / `store_failed`), И нынешние английские строки —
     * поэтому переход моста на коды не потребует новых правок Kotlin. Неизвестный ответ
     * возвращается как есть: скрыть причину совсем хуже, чем показать её техническим текстом,
     * а выдумывать перевод для незнакомой строки нельзя.
     */
    private fun bridgeErrorText(raw: String): String {
        val key = raw.trim()
        return when {
            key.isEmpty() -> getString(R.string.err_unknown, key)
            key == "invalid_domain" -> getString(R.string.err_invalid_domain)
            key == "duplicate" -> getString(R.string.err_duplicate)
            key == "store_failed" -> getString(R.string.err_store_failed)
            key == "not initialized" -> getString(R.string.err_not_initialized)
            key == "failed to add" -> getString(R.string.err_invalid_domain)
            key == "not found or builtin" -> getString(R.string.err_builtin_readonly)
            key.startsWith("rule not found") -> getString(R.string.err_rule_not_found)
            else -> key
        }
    }

    // ─── Роль «Выход»: локальные IP-адреса для подсказки поля Host ────────────
    //
    // Живой инцидент 2026-08-28: Go-сторона (androidbridge.GetLocalIPCandidatesJSON,
    // net.Interfaces()) на реальном устройстве не смогла перечислить интерфейсы (вернула
    // "null") — вероятно, песочница Android-приложения (untrusted_app SELinux-контекст)
    // не даёт Go-рантайму то же, что даёт обычному процессу на Windows/Linux. Обходной путь —
    // штатный Android/Java API, которым приложения пользуются без специальных прав.
    //
    // Живой инцидент 2026-09-29 (тот же, что у Go-стороны — singbox.LocalIPCandidates): первым в
    // поле «Host» попадал не адрес, по которому телефон реально виден в сети, а адрес служебного
    // интерфейса. Поэтому пропускаем то, что физически не может быть адресом «Выхода» для
    // партнёра: tun* (в том числе собственный TUN APF, 172.19.0.1 — он приватный, и без фильтра
    // шёл бы наравне с настоящим Wi-Fi-адресом), dummy*, ppp*, lo и link-local 169.254/16
    // (APIPA — «адреса нет вообще»). Порядок: wlan*/eth* с частным адресом → прочие частные →
    // остальные (публичные и CGNAT — CGNAT isPrivateIPv4 нарочно не считает частным).
    private fun localIpCandidates(): List<Pair<String, String>> {
        val primary = mutableListOf<Pair<String, String>>()
        val privateOther = mutableListOf<Pair<String, String>>()
        val other = mutableListOf<Pair<String, String>>()
        // Тот же адрес, что APFVpnService.Builder.addAddress: имя интерфейса у VPN-сервиса
        // на части прошивок отличается от «tun0», но адрес фиксирован.
        val apfTunAddress = "172.19.0.1"
        val ifaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return emptyList()
        while (ifaces.hasMoreElements()) {
            val iface = ifaces.nextElement()
            if (!iface.isUp || iface.isLoopback) continue
            val name = iface.name.lowercase()
            if (name == "lo" || name.startsWith("tun") || name.startsWith("dummy") || name.startsWith("ppp")) continue
            val addrs = iface.inetAddresses
            while (addrs.hasMoreElements()) {
                val addr = addrs.nextElement()
                if (addr !is java.net.Inet4Address) continue
                val ip = addr.hostAddress ?: continue
                if (addr.isLinkLocalAddress || ip == apfTunAddress) continue
                val entry = ip to iface.displayName
                when {
                    !isPrivateIPv4(ip) -> other.add(entry)
                    name.startsWith("wlan") || name.startsWith("eth") -> primary.add(entry)
                    else -> privateOther.add(entry)
                }
            }
        }
        return primary + privateOther + other
    }

    /** Предупреждение о хосте ссылки от Go-моста; пусто, если хост нормален для внешней сети или
     * вызов моста не удался — это подсказка, а не условие работы (как и при сборке ссылки). */
    private fun linkHostWarningOrEmpty(host: String): String =
        try { ApfCore.linkHostWarning(host) } catch (e: Exception) { "" }

    private fun isPrivateIPv4(ip: String): Boolean {
        val parts = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (parts.size != 4) return false
        return parts[0] == 10 ||
            (parts[0] == 172 && parts[1] in 16..31) ||
            (parts[0] == 192 && parts[1] == 168)
    }

    // ─── Справка по настройкам ───────────────────────────────────────────────

    /**
     * Э-UI-8 (docs/TZ_APF_QA_AND_BACKLOG_v1.0.md §4): минимальная справка по настройкам —
     * НЕ полная 5-wizard система (FR-9, отдельный будущий пункт), а короткое пояснение по
     * тапу на «ⓘ»: что делает настройка, что будет при вкл/выкл, есть ли риски. Пользователь
     * прямо просил «чтобы мог изучить что за настройку он хочет включить/отключить и к чему
     * это приведёт».
     *
     * LOT-K1: у справки появилась необязательная кнопка действия (setNeutralButton). Она
     * нужна там, где объяснение заканчивается требованием что-то сделать в другом месте
     * системы, — тогда «Понятно» оставляет пользователя ровно там же, откуда он пришёл.
     * Оба параметра со значением по умолчанию: все прежние вызовы showInfo(text) работают
     * без изменений и кнопки не получают.
     */
    private fun showInfo(
        text: String,
        actionLabel: String? = null,
        action: (() -> Unit)? = null
    ) {
        // Длинные пояснения (напр. инструкция по пробросу порта) обрезались стандартным
        // setMessage на невысоких экранах — оборачиваем текст в ScrollView, чтобы он всегда
        // прокручивался и читался целиком.
        val tv = TextView(this).apply {
            this.text = text
            setTextColor(getColor(android.R.color.white))
            textSize = 15f
            setTextIsSelectable(true)
            setPadding(64, 40, 64, 24)
        }
        val builder = AlertDialog.Builder(this)
            .setView(ScrollView(this).apply { addView(tv) })
            .setPositiveButton("Понятно", null)
        if (actionLabel != null && action != null) {
            builder.setNeutralButton(actionLabel) { _, _ -> action() }
        }
        builder.show()
    }

    /** «ⓘ»-иконка для настроек, собираемых программно внутри диалогов (не через XML —
     * там иконки уже в activity_main.xml, см. initViews). По тапу — showInfo(explanation). */
    private fun infoIcon(explanation: String): TextView = TextView(this).apply {
        text = "ⓘ"
        textSize = 16f
        setTextColor(getColor(android.R.color.darker_gray))
        setPadding(0, 0, 16, 0)
        setOnClickListener { showInfo(explanation) }
    }

    /**
     * Роль «Выход» (Э-Выход-2, docs/PLAN_APF_VHOD_VYHOD_v1.0.md) — первый экран для
     * mobile/androidbridge/server_role.go, без которого новый Go/Kotlin-мост нечем
     * вызывать. Явно помечен «эксперимент»: акцептанс Э-Выход-2 (роль переживает Doze
     * минимум 5 минут) ещё не пройден, и ТЗ §5.4 требует честного предупреждения о
     * меньшей надёжности на Android, а не мелкого шрифта.
     *
     * Требует того же согласия VpnService.prepare(), что и режим VPN клиента — роль
     * без TUN, но ProtectCallback (this.protect(fd) внутри APFVpnService) работает
     * только для приложения, которому пользователь разрешил быть VPN-сервисом
     * (см. комментарий у startServerRole в APFVpnService.kt). Отдельный поток
     * согласия здесь не строится — эта сборка уже проходила VpnService.prepare()
     * через режим VPN клиента; если согласия нет, отказ честный, с понятным текстом,
     * а не попытка развернуть второй консент-флоу поверх уже существующего.
     */
    private fun showServerRoleDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        fun header(text: String) {
            container.addView(TextView(this).apply {
                this.text = text
                setTextColor(getColor(android.R.color.darker_gray))
                setPadding(0, 24, 0, 8)
            })
        }

        container.addView(TextView(this).apply {
            text = "На телефоне эта роль менее надёжна: экономия батареи может " +
                "останавливать соединение, когда экран выключен. Для круглосуточной " +
                "работы лучше ПК или роутер с поддержкой VPN (см. Справка)."
            setTextColor(getColor(android.R.color.holo_orange_light))
            setPadding(0, 0, 0, 12)
        })

        val tvStatus = TextView(this).apply { setPadding(0, 0, 0, 12) }
        container.addView(tvStatus)
        // §5 (docs/PLAN_2026-08-28_stubs_and_realfunc.md): раньше никак не было видно, есть
        // ли вообще подключённые «Входы» — пользователь мог только гадать по факту наличия
        // интернета у партнёра. -1/отсутствие поля значит «не удалось узнать» (сервер только
        // стартовал), это НЕ то же самое, что «0 подключений» — различаем текстом явно.
        fun refreshStatus() {
            val s = try { JSONObject(ApfCore.getServerRoleStatusJson()) } catch (e: Exception) { null }
            val running = s?.optBoolean("running", false) ?: false
            val port = s?.optInt("listen_port", 0) ?: 0
            if (!running) {
                tvStatus.text = "Статус: остановлена"
                return
            }
            val count = if (s != null && s.has("connected_clients_count")) s.optInt("connected_clients_count", -1) else -1
            val clientsPart = if (count >= 0) ", подключено «Входов»: $count" else ", подключено «Входов»: неизвестно"
            val lastIp = s?.optString("last_client_ip", "") ?: ""
            val lastIpPart = if (lastIp.isNotEmpty()) " (последний: $lastIp)" else ""
            // [консилиум, MEDIUM, находка №24, TZ_RELAY_HARDENING_2026-08-29.md кластер H]
            // Раньше relay_exit_connected нигде здесь не читался — пользователь не мог
            // отличить «relay не настроен» от «настроен, но сейчас не подключён» (например,
            // ExitClient в backoff-паузе после обрыва — молчаливо, без единого признака в UI).
            // Поле отсутствует в JSON, если relay-адрес не задавался последнему
            // StartServerRole (см. GetServerRoleStatusJSON в server_role.go) — три состояния,
            // не два.
            val relayPart = if (s != null && s.has("relay_exit_connected")) {
                if (s.optBoolean("relay_exit_connected", false)) ", relay: подключён"
                else ", relay: задан, но не подключён"
            } else ""
            tvStatus.text = "Статус: работает, порт $port$clientsPart$lastIpPart$relayPart"
        }
        refreshStatus()

        // Живая находка 2026-08-25: раньше refreshStatus() читался один раз при открытии
        // и один раз через фиксированные 2с после нажатия «Запустить» — если диалог
        // оставляли открытым дольше или запуск занимал больше 2с, текст замирал на
        // устаревшем снимке (например, «порт 0», хотя на деле уже слушает 28443, или
        // наоборот — роль успела упасть, а текст всё ещё «работает»). Живой опрос раз в
        // 1.5с, пока диалог открыт — снимается через statusHandler в setOnDismissListener
        // ниже, чтобы не крутиться вхолостую после закрытия.
        val statusHandler = Handler(Looper.getMainLooper())
        val statusPoller = object : Runnable {
            override fun run() {
                refreshStatus()
                statusHandler.postDelayed(this, 1500)
            }
        }
        statusHandler.postDelayed(statusPoller, 1500)

        header("Идентичность звена")
        container.addView(infoRow(
            "Независимый ключ этого звена цепочки (UUID + Reality-пара). Генерируется " +
                "один раз, не при каждом запуске — тот же ключ нужен для ссылки, которую " +
                "получит «Вход». Живёт только на время этого сеанса приложения (эксперимент, " +
                "постоянного хранения ещё нет)."
        ))
        val tvIdentity = TextView(this).apply {
            text = if (serverRoleIdentityJson.isEmpty()) "не сгенерирована"
            else try {
                "UUID: " + JSONObject(serverRoleIdentityJson).optString("UUID")
            } catch (e: Exception) { "не сгенерирована" }
            setPadding(0, 0, 0, 8)
        }
        container.addView(tvIdentity)
        container.addView(Button(this).apply {
            // U-5 (словарь UI_CONTRACT §1.3 п.10): термин `identity` остаётся техническим
            // именем в скобках, а само действие названо по-русски.
            text = "Сгенерировать identity (ключ роли «Выход»)"
            setOnClickListener {
                serverRoleIdentityJson = ApfCore.generateServerIdentityJson()
                val uuid = try { JSONObject(serverRoleIdentityJson).optString("UUID") } catch (e: Exception) { "" }
                if (uuid.isEmpty()) {
                    toast(getString(R.string.t_identity_failed))
                } else {
                    tvIdentity.text = "UUID: $uuid"
                    toast(getString(R.string.t_identity_ok))
                }
            }
        })

        header("Запуск")
        val etPort = EditText(this).apply {
            hint = "Порт (1..65535)"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setText("28443")
        }
        container.addView(etPort)
        // U-5 (словарь UI_CONTRACT §1.3 п.9): «Reality SNI» — голый термин, по которому
        // пользователь не мог понять ни что вводить, ни можно ли оставить пусто.
        container.addView(infoRow(
            "SNI — имя сайта, под который маскируется соединение. Пусто — APF выберет " +
                "надёжное значение сам."
        ))
        val etRealityDest = EditText(this).apply {
            hint = "SNI для Reality (пусто — APF выберет сам)"
        }
        container.addView(etRealityDest)
        val etMaxClients = EditText(this).apply {
            hint = "Лимит устройств «Вход» (пусто = 2 по умолчанию для телефона)"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }
        container.addView(etMaxClients)
        // Фаза E (docs/PLAN_APF_RELAY_v1.0.md, docs/TZ_APF_RELAY_v1.0.md §1, §6): без relay
        // ссылка/подключение работают только там, где «Вход» физически может достучаться до
        // этого порта напрямую (одна сеть, проброс порта, публичный IP) — relay нужен, когда
        // это устройство за CGNAT/симметричным NAT (типичный случай мобильного интернета).
        container.addView(infoRow(
            "Relay — необязательный промежуточный сервер с публичным IP (свой VPS/Raspberry " +
                "Pi или готовый хостинг), через который «Вход» достучится до этого «Выхода», " +
                "даже если телефон сидит за CGNAT мобильного оператора и напрямую недостижим " +
                "(проброс порта на роутере тогда не поможет — это ограничение оператора, не " +
                "роутера). Если оба устройства в одной Wi-Fi сети или у этого телефона есть " +
                "публичный/проброшенный адрес — оставьте поле пустым."
        ))
        val etRelayAddr = EditText(this).apply {
            hint = "Адрес relay-сервера host:port (пусто = без relay)"
        }
        container.addView(etRelayAddr)
        // TZ_RELAY_HARDENING_2026-08-29.md кластер B: весь relay-трафик идёт через TLS с
        // закреплённым отпечатком сертификата (pinned-fingerprint — у самостоятельно
        // поднятого relay в общем случае нет ни домена, ни сертификата от публичного CA).
        // Оператор relay (apf-relay) печатает это значение в лог при первом запуске.
        val etRelayFingerprint = EditText(this).apply {
            hint = "Отпечаток TLS-сертификата relay (обязателен вместе с адресом)"
        }
        container.addView(etRelayFingerprint)
        container.addView(Button(this).apply {
            text = "Запустить роль «Выход»"
            setOnClickListener {
                if (serverRoleIdentityJson.isEmpty()) {
                    toast(getString(R.string.t_identity_first))
                    return@setOnClickListener
                }
                val port = etPort.text.toString().toIntOrNull()
                if (port == null || port !in 1..65535) {
                    toast(getString(R.string.t_need_port))
                    return@setOnClickListener
                }
                val maxClients = etMaxClients.text.toString().trim().toIntOrNull() ?: 0
                val relayAddr = etRelayAddr.text.toString().trim()
                val relayFingerprint = etRelayFingerprint.text.toString().trim()
                if (relayAddr.isNotEmpty() && relayFingerprint.isEmpty()) {
                    showErrorMessage(getString(R.string.t_relay_need_fingerprint))
                    return@setOnClickListener
                }
                if (VpnService.prepare(this@MainActivity) != null) {
                    showErrorMessage(getString(R.string.t_no_vpn_consent))
                    return@setOnClickListener
                }
                val intent = Intent(this@MainActivity, APFVpnService::class.java).apply {
                    action = APFVpnService.ACTION_START_SERVER_ROLE
                    putExtra(APFVpnService.EXTRA_SERVER_PORT, port)
                    putExtra(APFVpnService.EXTRA_SERVER_REALITY_DEST, etRealityDest.text.toString().trim())
                    putExtra(APFVpnService.EXTRA_SERVER_IDENTITY, serverRoleIdentityJson)
                    putExtra(APFVpnService.EXTRA_SERVER_MAX_CLIENTS, maxClients)
                    putExtra(APFVpnService.EXTRA_SERVER_RELAY_ADDR, relayAddr)
                    putExtra(APFVpnService.EXTRA_SERVER_RELAY_FINGERPRINT, relayFingerprint)
                }
                startForegroundService(intent)
                toast(getString(R.string.t_server_role_starting, port))
                tvStatus.postDelayed({ refreshStatus() }, 2000)
            }
        })
        container.addView(Button(this).apply {
            text = "Остановить роль «Выход»"
            setOnClickListener {
                val intent = Intent(this@MainActivity, APFVpnService::class.java).apply {
                    action = APFVpnService.ACTION_STOP_SERVER_ROLE
                }
                startService(intent)
                toast(getString(R.string.t_server_role_stopping))
                tvStatus.postDelayed({ refreshStatus() }, 1500)
            }
        })

        header("Ссылка для «Входа»")
        container.addView(infoRow(
            "Host — адрес, по которому «Вход» физически достучится до этого звена " +
                "(домен/IP). Ниже подставлен локальный IP этого телефона (для связи в " +
                "одной Wi-Fi сети) — для связи между разными сетями/странами нажмите " +
                "«Определить автоматически» (UPnP-проброс порта на роутере или, если " +
                "роутер не поддерживает UPnP, вероятный внешний IP через STUN — тогда " +
                "проброс порта нужно настроить на роутере вручную)."
        ))
        val etHost = EditText(this).apply { hint = "Host (домен или IP)" }
        container.addView(etHost)
        val tvHostHint = TextView(this).apply {
            setTextColor(getColor(android.R.color.darker_gray))
            textSize = 12f
            setPadding(0, 0, 0, 8)
        }
        container.addView(tvHostHint)
        // Живой инцидент 2026-08-28: androidbridge.GetLocalIPCandidatesJSON (Go, net.Interfaces())
        // на реальном устройстве вернул буквально "null" — Go-рантайм внутри песочницы
        // Android-приложения (untrusted_app SELinux-контекст) не смог перечислить сетевые
        // интерфейсы тем же способом, что успешно работает в обычном Go-процессе на Windows/
        // Linux. Обходной путь — не через Go-мост вовсе, а штатный Android/Java API
        // (java.net.NetworkInterface), которым приложения пользуются без специальных прав —
        // localIpCandidates() ниже.
        try {
            val candidates = localIpCandidates()
            if (candidates.isNotEmpty()) {
                if (etHost.text.isBlank()) etHost.setText(candidates[0].first)
                val parts = candidates.map { "${it.first} (${it.second})" }
                tvHostHint.text = if (parts.size > 1)
                    "Обнаружены адреса: ${parts.joinToString(", ")} — выберите тот, что физически достижим для «Входа»"
                else "Обнаружен адрес: ${parts[0]}"
            }
        } catch (e: Exception) {
            Log.e("APFVpnService", "localIpCandidates провалился", e)
        }
        // Поле ссылки, её предупреждение и сборка ссылки объявлены ЗДЕСЬ, до кнопки «Определить адрес
        // автоматически» (в контейнер добавляются ниже, в прежнем порядке): подстановка найденного адреса
        // в «Host» должна тут же пересобрать уже показанную ссылку, как это делает окно ПК
        // (doGenerateServerLink(true)) — иначе владелец скопирует ссылку со старым хостом и решит, что
        // «IP не меняется» (ревью 2026-09-30).
        val etLink = EditText(this).apply {
            hint = "Ссылка появится здесь"
            isFocusable = true
            setTextIsSelectable(true)
        }
        // Живой инцидент 2026-09-29: ссылка на приватный адрес (10.x.x.x, 192.168.x.x) собирается
        // «успешно», но «Вход» из ДРУГОЙ сети до неё не достучится (dial tcp ...: i/o timeout) —
        // причину нигде не объясняли. Текст даёт ApfCore.linkHostWarning; цвет — тот же
        // оранжевый предупреждения, что у плашки про надёжность роли в начале этого диалога.
        // Скрыт, пока нечего сказать (нет ссылки или адрес публичный).
        val tvLinkWarning = TextView(this).apply {
            setTextColor(getColor(android.R.color.holo_orange_light))
            textSize = 12f
            setPadding(0, 0, 0, 8)
            visibility = View.GONE
        }
        /** Сборка ссылки из полей диалога. silent=true — пересборка после автоопределения адреса:
         * без тостов и диалога ошибки, при нехватке данных молча выходим (ссылка остаётся прежней). */
        fun buildServerLinkFromFields(silent: Boolean) {
            if (serverRoleIdentityJson.isEmpty()) {
                if (!silent) toast(getString(R.string.t_identity_first))
                return
            }
            val relayAddr = etRelayAddr.text.toString().trim()
            val relayFingerprint = etRelayFingerprint.text.toString().trim()
            val host = etHost.text.toString().trim()
            // При relay host в ссылку не идёт (BuildServerLinkJSON игнорирует его в этом
            // случае, докс §3) — не требуем ввода того, что всё равно отбросится.
            if (host.isEmpty() && relayAddr.isEmpty()) {
                if (!silent) toast(getString(R.string.t_need_host))
                return
            }
            if (relayAddr.isNotEmpty() && relayFingerprint.isEmpty()) {
                if (!silent) showErrorMessage(getString(R.string.t_relay_need_fingerprint))
                return
            }
            val port = etPort.text.toString().toIntOrNull() ?: 0
            val result = try {
                JSONObject(ApfCore.buildServerLinkJson(
                    serverRoleIdentityJson, host, port, etRealityDest.text.toString().trim(), "APF", relayAddr, relayFingerprint
                ))
            } catch (e: Exception) {
                null
            }
            val link = result?.optString("link").orEmpty()
            if (link.isEmpty()) {
                if (!silent) {
                    val reason = result?.optString("error").orEmpty()
                    showErrorMessage(
                        getString(
                            R.string.e_build_link,
                            if (reason.isEmpty()) "причина не сообщена" else bridgeErrorText(reason)
                        )
                    )
                }
            } else {
                etLink.setText(link)
                // Предупреждение только для прямой ссылки: при заданном relay ссылка адресует
                // посредника, а не host (см. комментарий выше), и топология сети этого
                // телефона партнёра не касается. Сбой вызова моста не должен скрывать уже
                // собранную ссылку — это подсказка, а не условие работы.
                val warning = if (relayAddr.isEmpty()) {
                    try { ApfCore.linkHostWarning(host) } catch (e: Exception) { "" }
                } else ""
                if (warning.isEmpty()) {
                    tvLinkWarning.visibility = View.GONE
                } else {
                    tvLinkWarning.text = "⚠ Адрес «$host»: $warning"
                    tvLinkWarning.visibility = View.VISIBLE
                }
            }
        }
        val tvReachabilityResult = TextView(this).apply {
            textSize = 12f
            setPadding(0, 0, 0, 8)
        }
        container.addView(Button(this).apply {
            text = "🌐 Определить адрес автоматически"
            setOnClickListener {
                val port = etPort.text.toString().toIntOrNull()
                if (port == null || port !in 1..65535) {
                    toast(getString(R.string.t_need_port))
                    return@setOnClickListener
                }
                tvReachabilityResult.text = "Определяю доступность (UPnP → STUN, до 10с)..."
                // MulticastLock: без него Android может глушить входящий SSDP-мультикаст на
                // Wi-Fi-радио, и UPnP-часть ничего не найдёт даже при поддерживающем роутере
                // (см. комментарий у DetectReachabilityJSON, server_role.go).
                val wifi = applicationContext.getSystemService(WIFI_SERVICE) as? android.net.wifi.WifiManager
                val lock = wifi?.createMulticastLock("apf-upnp-discovery")
                lock?.acquire()
                Thread {
                    val raw = try { ApfCore.detectReachabilityJson(port) } finally { lock?.release() }
                    runOnUiThread {
                        try {
                            val r = JSONObject(raw)
                            if (r.has("error")) {
                                tvReachabilityResult.text = "✗ Не удалось определить: ${r.getString("error")}"
                                return@runOnUiThread
                            }
                            // method — internal/relay.Method: 0=Unknown 1=Direct 2=UPnP 3=ManualPort
                            // 4=Relay 5=Undetermined («не удалось определить», has_address=false).
                            val method = r.optInt("method", 0)
                            // Direct или UPnP — порт подтверждён; метод 5 — не «isGood» и не ошибка.
                            val isGood = method == 1 || method == 2
                            var text = (if (isGood) "✓ " else "ℹ ") + r.optString("explanation")
                            // Живой инцидент 2026-09-29 («IP не меняется», сначала на ПК): адрес
                            // подставлялся в «Host» только при Direct/UPnP или пустом поле, а поле уже
                            // заполнено локальным адресом при открытии диалога — STUN-результат его
                            // не заменял и в тексте не был виден. Теперь поле с заведомо бесполезным
                            // для другой сети значением (linkHostWarning непуст: LAN/loopback/CGNAT/
                            // 0.0.0.0) заменяется найденным ПУБЛИЧНЫМ адресом; нормальное значение
                            // пользователя (публичный IP/домен) не затираем; приватный/CGNAT-адрес
                            // (method 4) не подставляем никогда. Правило единое для Direct/UPnP/STUN
                            // (ревью 2026-09-30: раньше Direct/UPnP подставлялись безусловно — приватный
                            // адрес роутера при двойном NAT выдавался за «всё готово», а ручной домен
                            // затирался IP-адресом), как в окне ПК (doDetectReachability).
                            val hasAddress = r.optBoolean("has_address")
                            val extHost = r.optString("external_host")
                            val extPort = r.optInt("external_port")
                            val curHost = etHost.text.toString().trim()
                            var filled = false
                            var foundPublic = false
                            if (hasAddress) {
                                foundPublic = method != 4 && linkHostWarningOrEmpty(extHost).isEmpty()
                                val curUseless = curHost.isEmpty() || linkHostWarningOrEmpty(curHost).isNotEmpty()
                                filled = foundPublic && curUseless
                                val was = if (curHost.isNotEmpty()) ", было «$curHost»" else ""
                                text += when {
                                    // Причин недостижимости несколько (внутренний адрес, тест-диапазон
                                    // 198.18/15, операторский CGNAT) — называем нейтрально.
                                    !foundPublic ->
                                        " — найденный адрес $extHost недостижим снаружи (внутренний, " +
                                            "тестовый или операторский), поэтому в «Host» не подставлен"
                                    filled && isGood ->
                                        " — внешний адрес: $extHost:$extPort (подставлен в «Host»$was)"
                                    filled ->
                                        " — подставлен вероятный внешний адрес $extHost" +
                                            (if (curHost.isNotEmpty()) " (было «$curHost»)" else "") +
                                            " — ссылка заработает у партнёра после проброса порта $extPort или через relay"
                                    else ->
                                        " — внешний адрес: $extHost:$extPort (в «Host» не подставлен: " +
                                            "там уже введено «$curHost»)"
                                }
                            }
                            // Пояснение отдельным предложением: Explain(...) у Go иногда уже кончается
                            // точкой — без этой склейки получалось «..».
                            fun addSentence(s: String) {
                                text = text.trimEnd('.', ' ', '\n') + ". " + s
                            }
                            // Адрес есть, но он не публичный (у Go это method 4) — пробросом порта не
                            // лечится, только relay.
                            val relayOnly = method == 4 || (method == 3 && hasAddress && !foundPublic)
                            if (relayOnly) {
                                addSentence("Прямое подключение снаружи невозможно — используйте " +
                                    "relay-посредник (поля «Адрес relay-сервера» и его отпечаток выше).")
                            } else if (method == 3) {
                                // Тот же инцидент: устройство в раздаче с другого телефона (или на
                                // мобильном интернете) — «пробросьте порт на роутере» невыполнимо,
                                // настраиваемого роутера нет.
                                addSentence("Порт $port нужно пробросить на роутере вручную на этот же порт " +
                                    "локально. Если этот телефон сидит в раздаче с другого телефона " +
                                    "или на мобильном интернете — проброс невозможен, нужен relay " +
                                    "(поля «Адрес relay-сервера» и его отпечаток выше).")
                            } else if (method == 5) {
                                addSentence("Адрес в «Host» оставлен как есть — введите публичный адрес " +
                                    "или домен вручную либо задайте relay (поля выше).")
                            }
                            if (filled) {
                                etHost.setText(extHost)
                                // Ссылка, уже показанная ниже, собрана со СТАРЫМ хостом (и старым
                                // предупреждением) — без пересборки владелец скопировал бы прежний адрес
                                // и снова решил, что «IP не меняется» (то же делает окно ПК:
                                // doGenerateServerLink(true)).
                                if (etLink.text.isNotBlank()) {
                                    buildServerLinkFromFields(true)
                                    if (!isGood) {
                                        // Подставленный STUN-адрес НЕ подтверждён (порт не проброшен):
                                        // рядом со ссылкой честная пометка вместо молчания.
                                        tvLinkWarning.text = "ℹ В ссылке — вероятный внешний адрес $extHost, порт на нём " +
                                            "ещё не проброшен: у партнёра из другой сети ссылка заработает " +
                                            "после проброса порта или через relay."
                                        tvLinkWarning.visibility = View.VISIBLE
                                    }
                                }
                            }
                            tvReachabilityResult.text = text
                        } catch (e: Exception) {
                            tvReachabilityResult.text = "✗ Не удалось разобрать ответ: $e"
                        }
                    }
                }.start()
            }
        })
        container.addView(tvReachabilityResult)

        header("Проброс порта на роутере")
        container.addView(Button(this).apply {
            text = "📖 Как пробросить порт на роутере"
            setOnClickListener {
                showInfo(
                    "Зачем: чтобы «Вход» из ДРУГОЙ сети или страны достучался до этого «Выхода», " +
                    "роутер должен направлять входящие подключения на нужный порт именно на этот телефон.\n\n" +
                    "Шаги:\n" +
                    "1) Узнайте локальный IP телефона: Настройки → Wi-Fi → ваша сеть (обычно 192.168.x.x). " +
                    "Он уже подставлен в поле «Host» выше.\n" +
                    "2) Порт — значение из поля «Порт» выше (по умолчанию 28443).\n" +
                    "3) Откройте админку роутера в браузере: обычно http://192.168.0.1 или http://192.168.1.1 " +
                    "(точный адрес, логин и пароль — на наклейке снизу роутера).\n" +
                    "4) Найдите раздел «Переадресация портов» / «Port Forwarding» / «Virtual Server» / «NAT» " +
                    "(часто внутри «Дополнительно» / «Advanced»).\n" +
                    "5) Создайте правило:\n" +
                    "   • Внешний порт (WAN / External): 28443 — тот же, что в APF;\n" +
                    "   • Внутренний порт (LAN / Internal): 28443 — тот же;\n" +
                    "   • Внутренний IP (Device / Internal IP): локальный IP телефона из шага 1;\n" +
                    "   • Протокол: TCP (можно TCP/UDP);\n" +
                    "   • Включить (Enable): да.\n" +
                    "6) Сохраните и примените (роутер может перезагрузиться).\n" +
                    "7) Внешний адрес для ссылки «Входу» = ваш публичный IP (виден в статусе WAN роутера " +
                    "или на сайте «мой IP»). Ссылка будет вида ПУБЛИЧНЫЙ_IP:28443.\n\n" +
                    "Важно:\n" +
                    "• Если у провайдера «серый» IP (CGNAT — типично для мобильного, иногда домашнего " +
                    "интернета), проброс на роутере НЕ поможет: оператор всё равно не пропустит входящее. " +
                    "Тогда используйте Relay (поле выше) или закажите у провайдера «белый» / публичный IP.\n" +
                    "• Если роутер поддерживает UPnP — кнопка «Определить адрес автоматически» выше может " +
                    "пробросить порт сама; ручная настройка нужна, только если UPnP выключен или не поддерживается.\n" +
                    "• Не меняйте локальный IP телефона (лучше закрепить его в роутере — DHCP-резервация " +
                    "по MAC-адресу), иначе правило перестанет работать."
                )
            }
        })
        // etLink/tvLinkWarning и buildServerLinkFromFields объявлены выше (до кнопки автоопределения:
        // она пересобирает показанную ссылку после подстановки найденного адреса).
        container.addView(etLink)
        container.addView(tvLinkWarning)
        container.addView(Button(this).apply {
            text = "Собрать ссылку"
            setOnClickListener { buildServerLinkFromFields(false) }
        })

        AlertDialog.Builder(this)
            .setTitle("Роль «Выход» (эксперимент)")
            .setView(ScrollView(this).apply { addView(container) })
            .setPositiveButton("Закрыть", null)
            .setOnDismissListener { statusHandler.removeCallbacks(statusPoller) }
            .show()
    }

    /** Строка «ⓘ Что это?» — компактная справка для группы настроек под общим заголовком
     * (header(...)), когда оборачивать в иконку каждый Switch по отдельности избыточно. */
    private fun infoRow(explanation: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = android.view.Gravity.CENTER_VERTICAL
        setPadding(0, 0, 0, 8)
        addView(infoIcon(explanation))
        addView(TextView(this@MainActivity).apply {
            text = "Что это?"
            setTextColor(getColor(android.R.color.darker_gray))
            textSize = 12f
            setOnClickListener { showInfo(explanation) }
        })
    }
}
