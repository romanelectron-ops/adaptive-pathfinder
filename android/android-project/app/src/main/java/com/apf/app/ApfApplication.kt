package com.apf.app

import android.app.Application

/**
 * Точка входа процесса — единственное место, гарантированно выполняющееся раньше ЛЮБОГО
 * компонента (Activity/Service/BroadcastReceiver), поэтому именно здесь ставится глобальный
 * перехватчик необработанных исключений: и MainActivity, и APFVpnService, и BootReceiver
 * могут крашиться независимо друг от друга (например, служба может упасть без открытой
 * Activity — восстановление после смерти процесса), а лог должен ловить оба случая.
 * Штатный обработчик (системный диалог «Приложение остановлено» / отчёт в Play Console)
 * вызывается ПОСЛЕ записи — эта функция не подменяет крах-репортинг системы, только
 * добавляет запись в файл ДО него.
 */
class ApfApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ApfFileLogger.init(this)

        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                ApfFileLogger.logThrowable("CRASH(${thread.name})", throwable)
            } catch (_: Throwable) {
                // Запись краша не имеет права помешать штатной обработке краша.
            }
            previousHandler?.uncaughtException(thread, throwable)
        }
    }
}
