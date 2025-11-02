# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# ============ 安全检测模块保护规则 ============

# 保留所有 security 包下的类和方法
# 这些类包含 native 方法，不能被混淆
-keep class com.grtsinry43.environmentdetector.security.** { *; }

# 保留 native 方法
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留 DetectionType 枚举
-keepclassmembers enum com.grtsinry43.environmentdetector.security.DetectionType {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# 额外的安全措施：移除日志
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# 但保留警告和错误日志（用于安全检测）
# -assumenosideeffects class android.util.Log {
#     public static *** w(...);
#     public static *** e(...);
# }
