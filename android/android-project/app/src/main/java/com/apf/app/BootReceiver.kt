package com.apf.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * BootReceiver — автозапуск APF при загрузке устройства.
 * Запускается только если пользователь включил автозапуск в настройках.
 *
 * C-9 (ТЗ v1.4, Q7). Раньше здесь безусловно поднимался режим «прокси», даже если
 * пользователь выбрал «Режим VPN» — то есть после перезагрузки телефон оказывался в
 * прокси-режиме при включённом тумблере VPN, и экран говорил одно, а работало другое.
 * Пока автозапуск выключен по умолчанию, расхождение никого не задевало; с `auto_start`
 * это ровно тот класс молчаливой подмены защиты, который чинит всё ТЗ.
 *
 * Оба ключа лежат в ОДНОМ файле настроек `apf_prefs` — том же, что читает и пишет
 * MainActivity (K2-A, П2a): второй файл настроек на одно приложение — это будущий вопрос
 * «а в каком из них правда».
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // Локальная переменная называется НЕ action намеренно: ниже внутри apply { }
        // присваивание `action = …` разрешалось бы в эту локальную val, а не в поле
        // Intent — Kotlin отдаёт приоритет локальной области перед неявным получателем.
        // Компилятор ловил это как «Val cannot be reassigned», и файл не собирался.
        val received = intent.action ?: return
        if (received != Intent.ACTION_BOOT_COMPLETED &&
            received != Intent.ACTION_MY_PACKAGE_REPLACED) return

        val prefs = context.getSharedPreferences(MainActivity.UI_PREFS, Context.MODE_PRIVATE)
        val autoStart = prefs.getBoolean("auto_start", false)
        if (!autoStart) return

        val wantsVpn = prefs.getBoolean(MainActivity.KEY_VPN_MODE, false)

        // Согласие на VpnService может дать ТОЛЬКО активити (системный диалог), приёмник
        // на загрузке показать его не может. VpnService.prepare() возвращает null, когда
        // согласие уже выдано в прошлом сеансе — только в этом случае режим VPN поднимается
        // без участия человека. Иначе — честная деградация в «прокси» с причиной, которую
        // пользователь увидит в уведомлении службы, а не молчаливая подмена режима.
        val consentMissing = wantsVpn && VpnService.prepare(context) != null

        val serviceIntent = Intent(context, APFVpnService::class.java)
        if (wantsVpn && !consentMissing) {
            Log.i("APFBoot", "Автозапуск APF в режиме VPN (согласие уже выдано)")
            serviceIntent.action = APFVpnService.ACTION_CONNECT_VPN
        } else {
            Log.i(
                "APFBoot",
                if (consentMissing) "Автозапуск APF: выбран режим VPN, но системного согласия " +
                    "нет — поднимаю прокси"
                else "Автозапуск APF в режиме прокси"
            )
            serviceIntent.action = APFVpnService.ACTION_CONNECT_PROXY
            if (consentMissing) {
                serviceIntent.putExtra(
                    APFVpnService.EXTRA_START_NOTICE,
                    "Выбран режим VPN, но системное разрешение на туннель после перезагрузки " +
                        "не подтверждено — APF поднял режим «Прокси». Откройте APF и нажмите " +
                        "«Подключить», чтобы разрешить VPN."
                )
            }
        }
        context.startForegroundService(serviceIntent)
    }
}
