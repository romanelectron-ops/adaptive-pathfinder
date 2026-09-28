package com.apf.app

import android.content.Context
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Постоянный файл диагностики (просьба пользователя 2026-08-18): если у приложения что-то
 * идёт не так — сбой, вылет, странное поведение движка — обычный пользователь без доступа
 * к adb/logcat должен суметь выгрузить один файл и прислать его разработчику. Пишет в
 * files/logs/apf_log.txt (уже объявлен в res/xml/file_paths.xml для FileProvider).
 *
 * Файл целиком перезаписывается заново раз в 72 часа (не растёт бесконечно годами) — а не
 * докручивается набором ротируемых частей, читать один файл проще. Аварийный предел по
 * размеру (10 МБ) страхует от патологически быстрого разрастания между переписываниями
 * (например, если движок зациклится в шумном DEBUG-логировании).
 *
 * Источники записей: ApfCore.onLog (уже покрывает и клиентский, и серверный поток — см.
 * [SINGBOX/...]/[SERVER/...] префиксы, [[apf-vyhod2-android-go-layer-2026-08-18]]),
 * ApfCore.onLeak, несколько ключевых точек жизненного цикла APFVpnService, и необработанные
 * исключения (см. ApfApplication — устанавливает Thread.setDefaultUncaughtExceptionHandler).
 */
object ApfFileLogger {
    private const val MAX_AGE_MS = 72L * 60 * 60 * 1000
    private const val MAX_SIZE_BYTES = 10L * 1024 * 1024
    private const val HEADER_PREFIX = "# APF log epoch="

    private val timeFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    private val lock = Any()

    private var logFile: File? = null
    private var writer: BufferedWriter? = null
    private var epochMs: Long = 0
    private var approxSize: Long = 0

    fun init(context: Context) {
        synchronized(lock) {
            if (logFile != null) return
            val dir = File(context.filesDir, "logs")
            if (!dir.exists()) dir.mkdirs()
            val f = File(dir, "apf_log.txt")
            logFile = f
            val existingEpoch = if (f.exists()) readEpoch(f) else null
            val expired = existingEpoch == null ||
                System.currentTimeMillis() - existingEpoch > MAX_AGE_MS ||
                f.length() > MAX_SIZE_BYTES
            if (expired) {
                resetFileLocked(f)
            } else {
                epochMs = existingEpoch!!
                approxSize = f.length()
                openWriterLocked(f)
            }
        }
    }

    /** level — короткий код (I/W/E/D/CRASH), tag — источник (APFVpnService, MainActivity, …). */
    fun log(level: String, tag: String, message: String) {
        val f = logFile ?: return
        synchronized(lock) {
            if (System.currentTimeMillis() - epochMs > MAX_AGE_MS || approxSize > MAX_SIZE_BYTES) {
                resetFileLocked(f)
            }
            val line = "${timeFmt.format(Date())} [$level/$tag] $message\n"
            try {
                writer?.write(line)
                writer?.flush()
                approxSize += line.length
            } catch (_: Throwable) {
                // Диагностический лог не имеет права уронить приложение — пропускаем сбой I/O.
            }
        }
    }

    fun logThrowable(tag: String, throwable: Throwable) {
        log("CRASH", tag, throwable.stackTraceToString())
    }

    /** Файл для выгрузки (Intent.ACTION_SEND через FileProvider) — null, пока init() не звался. */
    fun file(): File? = logFile

    private fun resetFileLocked(f: File) {
        try {
            writer?.close()
        } catch (_: Throwable) {
        }
        epochMs = System.currentTimeMillis()
        approxSize = 0
        try {
            f.writeText("$HEADER_PREFIX$epochMs\n")
        } catch (_: Throwable) {
        }
        openWriterLocked(f)
    }

    private fun openWriterLocked(f: File) {
        writer = try {
            BufferedWriter(OutputStreamWriter(FileOutputStream(f, true)))
        } catch (_: Throwable) {
            null
        }
    }

    private fun readEpoch(f: File): Long? = try {
        f.bufferedReader().useLines { lines ->
            val first = lines.firstOrNull()
            if (first == null || !first.startsWith(HEADER_PREFIX)) null
            else first.removePrefix(HEADER_PREFIX).trim().toLongOrNull()
        }
    } catch (_: Throwable) {
        null
    }
}
