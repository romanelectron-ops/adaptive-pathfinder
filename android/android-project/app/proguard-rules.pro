# Правила сжатия кода для release-сборки.
#
# Главное: gomobile-мост вызывается через JNI, и R8 не видит этих вызовов из байт-кода.
# Без явного сохранения классы моста будут вырезаны, и приложение упадёт при первом
# обращении к ядру — причём только в release-сборке, что делает дефект особенно неприятным.

# Мост APF (gomobile bind) и всё, что он генерирует.
-keep class androidbridge.** { *; }
-keep class go.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# Интерфейсы обратного вызова реализуются в Kotlin, а вызываются из Go через JNI.
-keep class * implements androidbridge.LogCallback { *; }
-keep class * implements androidbridge.StateCallback { *; }
-keep class * implements androidbridge.LeakCallback { *; }

# Собственные компоненты, объявленные в манифесте.
-keep class com.apf.app.APFVpnService { *; }
-keep class com.apf.app.MainActivity { *; }
-keep class com.apf.app.BootReceiver { *; }

# Сообщения об ошибках должны оставаться читаемыми в отчётах об испытаниях.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
