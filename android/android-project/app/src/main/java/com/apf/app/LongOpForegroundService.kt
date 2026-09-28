package com.apf.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.NotificationCompat

/**
 * Foreground-сервис на время долгих операций ядра, НЕ связанных с VPN-подключением: обход
 * пула («Сканировать все»), проба реального трафика («Собрать список рабочих узлов»),
 * харвест («Обновить узлы»/«Извлечь узлы из текста»). Для самого VPN-режима уже есть
 * отдельный APFVpnService — этот сервис его не заменяет и не трогает.
 *
 * ЗАЧЕМ (жалоба владельца 2026-09-22, issue 2). Уход на другую ВКЛАДКУ внутри приложения
 * уже проверен живьём и багом не является — Activity остаётся в памяти, горутины ядра
 * спокойно продолжают работу. Здесь закрывается более тяжёлый случай: приложение СВЁРНУТО
 * целиком или ЭКРАН ПОГАШЕН. Тогда возможны два независимых механизма обрыва операции:
 *   1) без wake lock CPU уходит в глубокий сон — выполнение (горутины, сетевые запросы)
 *      приостанавливается до следующего пробуждения устройства;
 *   2) Activity-процесс без единого foreground-компонента становится «кэшированным» —
 *      первый кандидат для system LMK при нехватке памяти, а на агрессивных прошивках
 *      (MIUI и подобные — телефон приёмки <test-phone> как раз на MIUI) процесс может быть
 *      добит собственным батарейным менеджером ещё раньше системного LMK.
 * Foreground-сервис с уведомлением снимает риск 2 (приоритет процесса поднят, доступ к сети
 * не режется Doze — это штатное исключение ОС для foreground-сервисов); partial wake lock
 * снимает риск 1 (CPU не спит, пока идёт операция).
 *
 * САМ СЕРВИС НИЧЕГО НЕ ЗАПУСКАЕТ И НЕ ОТМЕНЯЕТ. Он только наблюдает за
 * Androidbridge.anyLongOpRunning() (единая точка правды в Go-ядре сразу по всем трём
 * операциям, см. mobile/androidbridge/bridge.go) и завершает себя, как только она вернёт
 * false. Запускается вызовом ensureStarted() рядом с каждым местом в MainActivity, где
 * стартует одна из трёх операций (startSweep/startNodeCheck/harvestNow/harvestFromText).
 * Если одна операция стартует, пока сервис уже поднят другой (например харвест поверх
 * скана), повторный ensureStarted() — обычный Android-вызов onStartCommand на ту же
 * инстанцию сервиса; таймер жизни/wake lock не переинициализируются, а AnyLongOpRunning()
 * всё равно останется true, пока жива хотя бы одна из операций (это OR трёх флагов).
 */
class LongOpForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "apf_longop"
        const val NOTIF_ID = 1010
        private const val POLL_MS = 1500L

        // Страховка от зависшего флага на стороне ядра (баг/недостижимое "running=true"
        // навечно): сервис и wake lock не живут бесконечно, даже если движок почему-то не
        // сообщает о завершении. 30 минут — заведомо больше самого долгого легитимного
        // прогона («Все рабочие» на большом пуле, по опыту живых прогонов — единицы минут).
        private const val MAX_LIFETIME_MS = 30 * 60 * 1000L

        /**
         * Поднимает сервис, если он ещё не поднят. Безопасно звать многократно (в том числе
         * из нескольких мест подряд, если пользователь запустил две операции одну за другой).
         */
        fun ensureStarted(ctx: Context) {
            val intent = Intent(ctx, LongOpForegroundService::class.java)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ctx.startForegroundService(intent)
                } else {
                    ctx.startService(intent)
                }
            } catch (_: Exception) {
                // Не даём сбою запуска сервиса сорвать саму операцию — при провале старта
                // сервиса скан/харвест всё равно продолжится, просто без усиленной защиты
                // от Doze/LMK (тот же уровень надёжности, что был до этой доработки).
            }
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private var wakeLock: PowerManager.WakeLock? = null
    private var startedAt = 0L
    private var pollRunnable: Runnable? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Уже идёт (второй ensureStarted поверх первого) — не переинициализируем таймер
        // жизни и wake lock заново, просто продолжаем существующий цикл опроса.
        if (wakeLock?.isHeld == true) {
            return START_STICKY
        }
        startedAt = System.currentTimeMillis()
        startForeground(NOTIF_ID, buildNotification())
        acquireWakeLock()
        schedulePoll()
        return START_STICKY
    }

    private fun acquireWakeLock() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "APF:LongOpForegroundService"
            ).apply {
                setReferenceCounted(false)
                // Таймаут дублирует MAX_LIFETIME_MS на уровне ОС: даже если наш собственный
                // цикл опроса почему-то не сработает, систем сама снимет лок.
                acquire(MAX_LIFETIME_MS)
            }
        } catch (_: Exception) {
            // Без wake lock сервис всё равно держит foreground-приоритет (защита от LMK
            // остаётся), теряется только защита от глубокого сна CPU при погашенном экране.
        }
    }

    private fun schedulePoll() {
        val r = object : Runnable {
            override fun run() {
                val elapsed = System.currentTimeMillis() - startedAt
                val stillRunning = try {
                    ApfCore.anyLongOpRunning()
                } catch (_: Exception) {
                    false
                }
                if (!stillRunning || elapsed > MAX_LIFETIME_MS) {
                    stopSelfCleanly()
                    return
                }
                handler.postDelayed(this, POLL_MS)
            }
        }
        pollRunnable = r
        handler.postDelayed(r, POLL_MS)
    }

    private fun stopSelfCleanly() {
        pollRunnable?.let { handler.removeCallbacks(it) }
        pollRunnable = null
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (_: Exception) {
            // Снятие лока не должно ронять остановку сервиса.
        }
        wakeLock = null
    }

    override fun onDestroy() {
        pollRunnable?.let { handler.removeCallbacks(it) }
        releaseWakeLock()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "APF · Фоновые операции с узлами", NotificationManager.IMPORTANCE_LOW
            )
            channel.setShowBadge(false)
            channel.description = "Показывается, пока идёт сканирование, сбор рабочих узлов или харвест"
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): android.app.Notification {
        val openPending = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("APF: идёт проверка узлов")
            .setContentText("Сканирование / сбор рабочих узлов / харвест — не выгружайте приложение из недавних")
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setContentIntent(openPending)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
