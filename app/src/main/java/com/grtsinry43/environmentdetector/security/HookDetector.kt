package com.grtsinry43.environmentdetector.security

import android.content.Context
import dalvik.system.BaseDexClassLoader
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.lang.reflect.Modifier

/**
 * Hook 框架检测器
 * 检测 Xposed、LSPosed、Frida、Substrate、Riru、Zygisk 等 Hook 框架
 * 使用深度分析，避免简单的包名/文件检测
 */
class HookDetector(private val context: Context) : IDetector {

    companion object {
        // Hook 框架的典型类名特征（用于栈帧分析）
        private val HOOK_CLASS_PATTERNS = listOf(
            "de.robv.android.xposed",
            "io.github.lsposed",
            "com.elderdrivers.riru",
            "me.weishu",
            "com.saurik.substrate",
            "com.android.reverse"
        )

        // Frida 相关库名
        private val FRIDA_LIB_PATTERNS = listOf(
            "frida-agent",
            "frida-gadget",
            "frida",
            "re.frida"
        )
    }

    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 1. 栈帧分析
        checkStackTrace()?.let { results.add(it) }

        // 2. ClassLoader 异常检测
        checkClassLoaders()?.let { results.add(it) }

        // 3. 检测已加载的 Native 库
        checkLoadedNativeLibs()?.let { results.add(it) }

        // 4. 检测 Xposed/LSPosed 特征
        checkXposedFramework()?.let { results.add(it) }

        // 5. 检测 Frida
        checkFridaServer()?.let { results.add(it) }

        // 6. 检测 maps 文件中的可疑模块
        checkMemoryMaps()?.let { results.add(it) }

        // 7. 检测方法是否被 Hook
        checkMethodHooks()?.let { results.add(it) }

        // 8. 检测 Xposed 环境变量和系统属性
        checkXposedEnvironment()?.let { results.add(it) }

        // 9. 检测异常的异常处理器
        checkExceptionHandler()?.let { results.add(it) }

        // 移除方法调用时间检测，因为容易误报
        // 现代设备的性能波动、GC等都会影响时间测量

        return results
    }

    /**
     * 栈帧分析 - 检测调用栈中是否有可疑的 Hook 框架类
     */
    private fun checkStackTrace(): DetectionItem? {
        try {
            val throwable = Throwable()
            val stackTrace = throwable.stackTrace

            stackTrace.forEach { frame ->
                val className = frame.className
                HOOK_CLASS_PATTERNS.forEach { pattern ->
                    if (className.contains(pattern, ignoreCase = true)) {
                        return DetectionItem(
                            type = DetectionType.HOOK_XPOSED,
                            description = "Hook framework detected in stack trace",
                            isAbnormal = true,
                            details = mapOf(
                                "suspicious_class" to className,
                                "pattern_matched" to pattern
                            )
                        )
                    }
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * ClassLoader 异常检测
     * Hook 框架通常会注入额外的 ClassLoader
     */
    private fun checkClassLoaders(): DetectionItem? {
        try {
            var classLoader: ClassLoader? = context.classLoader
            val classLoaderChain = mutableListOf<String>()
            var depth = 0

            while (classLoader != null && depth < 10) {
                val loaderName = classLoader.javaClass.name
                classLoaderChain.add(loaderName)

                // 检测可疑的 ClassLoader
                if (loaderName.contains("xposed", ignoreCase = true) ||
                    loaderName.contains("epic", ignoreCase = true) ||
                    loaderName.contains("lsposed", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.HOOK_LSPOSED,
                        description = "Suspicious ClassLoader detected",
                        isAbnormal = true,
                        details = mapOf(
                            "classloader" to loaderName,
                            "chain" to classLoaderChain.joinToString(" -> ")
                        )
                    )
                }

                classLoader = classLoader.parent
                depth++
            }

            // 检测 DexClassLoader 的异常路径
            if (context.classLoader is BaseDexClassLoader) {
                try {
                    val pathListField = BaseDexClassLoader::class.java.getDeclaredField("pathList")
                    pathListField.isAccessible = true
                    val pathList = pathListField.get(context.classLoader)

                    val dexElementsField = pathList.javaClass.getDeclaredField("dexElements")
                    dexElementsField.isAccessible = true
                    val dexElements = dexElementsField.get(pathList) as Array<*>

                    // 正常应用的 dex 数量有限
                    if (dexElements.size > 10) {
                        return DetectionItem(
                            type = DetectionType.HOOK_XPOSED,
                            description = "Abnormal number of dex files loaded",
                            isAbnormal = true,
                            details = mapOf("dex_count" to dexElements.size.toString())
                        )
                    }
                } catch (e: Exception) {
                    // 忽略反射失败
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测已加载的 Native 库
     * 通过读取 /proc/self/maps 检测可疑的 .so 文件
     */
    private fun checkLoadedNativeLibs(): DetectionItem? {
        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                val content = mapsFile.readText()
                val suspiciousLibs = mutableListOf<String>()

                FRIDA_LIB_PATTERNS.forEach { pattern ->
                    if (content.contains(pattern, ignoreCase = true)) {
                        // 提取具体的库名
                        content.split("\n").forEach { line ->
                            if (line.contains(pattern, ignoreCase = true) && line.contains(".so")) {
                                val libName = line.substringAfterLast("/")
                                if (libName.isNotBlank() && !suspiciousLibs.contains(libName)) {
                                    suspiciousLibs.add(libName)
                                }
                            }
                        }
                    }
                }

                if (suspiciousLibs.isNotEmpty()) {
                    return DetectionItem(
                        type = DetectionType.HOOK_FRIDA,
                        description = "Frida library detected in memory",
                        isAbnormal = true,
                        details = mapOf("libraries" to suspiciousLibs.joinToString(", "))
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 Xposed/LSPosed 框架特征
     */
    private fun checkXposedFramework(): DetectionItem? {
        try {
            // 尝试反射获取 XposedBridge
            try {
                Class.forName("de.robv.android.xposed.XposedBridge")
                return DetectionItem(
                    type = DetectionType.HOOK_XPOSED,
                    description = "XposedBridge class found",
                    isAbnormal = true,
                    details = mapOf("framework" to "Xposed")
                )
            } catch (e: ClassNotFoundException) {
                // 预期的异常，继续
            }

            // 检测 LSPosed
            try {
                Class.forName("io.github.lsposed.lspd.core.Startup")
                return DetectionItem(
                    type = DetectionType.HOOK_LSPOSED,
                    description = "LSPosed class found",
                    isAbnormal = true,
                    details = mapOf("framework" to "LSPosed")
                )
            } catch (e: ClassNotFoundException) {
                // 预期的异常，继续
            }

            // 检测 EdXposed
            try {
                Class.forName("com.elderdrivers.riru.edxposed.core.Main")
                return DetectionItem(
                    type = DetectionType.HOOK_XPOSED,
                    description = "EdXposed class found",
                    isAbnormal = true,
                    details = mapOf("framework" to "EdXposed")
                )
            } catch (e: ClassNotFoundException) {
                // 预期的异常，继续
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 Frida Server
     */
    private fun checkFridaServer(): DetectionItem? {
        try {
            // 检测 Frida 默认端口
            val ports = listOf(27042, 27043, 27045)

            // 使用更可靠的方法检测端口
            val tcpFile = File("/proc/net/tcp")
            val tcp6File = File("/proc/net/tcp6")

            if (!tcpFile.exists() && !tcp6File.exists()) {
                // 无法访问 tcp 文件，不进行检测
                return null
            }

            val tcpContent = if (tcpFile.exists()) tcpFile.readText() else ""
            val tcp6Content = if (tcp6File.exists()) tcp6File.readText() else ""
            val allContent = tcpContent + tcp6Content

            ports.forEach { port ->
                // 转换端口为十六进制格式
                val portHex = port.toString(16).uppercase().padStart(4, '0')
                if (allContent.contains(":$portHex ")) {
                    return DetectionItem(
                        type = DetectionType.HOOK_FRIDA,
                        description = "Frida server port detected",
                        isAbnormal = true,
                        details = mapOf("port" to port.toString())
                    )
                }
            }
        } catch (e: Exception) {
            // 正常情况下可能无法访问这些文件
        }
        return null
    }

    /**
     * 检测 /proc/self/maps 中的可疑模块
     */
    private fun checkMemoryMaps(): DetectionItem? {
        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                val content = mapsFile.readText()

                // Riru/Zygisk 特征
                if (content.contains("libriru", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.HOOK_RIRU,
                        description = "Riru module detected in memory maps",
                        isAbnormal = true,
                        details = mapOf("source" to "/proc/self/maps")
                    )
                }

                // Zygisk 特征
                if (content.contains("zygisk", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.HOOK_ZYGISK,
                        description = "Zygisk detected in memory maps",
                        isAbnormal = true,
                        details = mapOf("source" to "/proc/self/maps")
                    )
                }

                // Substrate 特征
                if (content.contains("substrate", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.HOOK_SUBSTRATE,
                        description = "Substrate detected in memory maps",
                        isAbnormal = true,
                        details = mapOf("source" to "/proc/self/maps")
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测关键方法是否被 Hook
     * 通过检查方法实现的地址和签名
     */
    private fun checkMethodHooks(): DetectionItem? {
        try {
            // 检测常见的被 Hook 的方法
            val suspiciousMethods = mutableListOf<String>()

            // 检测 SSLContext 相关方法（JustTrustMe 等会 Hook）
            // 通过检查所有方法，找到名为 init 的方法
            try {
                val sslContextClass = Class.forName("javax.net.ssl.SSLContext")
                val methods = sslContextClass.declaredMethods

                for (method in methods) {
                    if (method.name == "init") {
                        // 检查方法的声明类是否被修改
                        if (method.declaringClass != sslContextClass) {
                            suspiciousMethods.add("SSLContext.init (declaring class mismatch)")
                            break
                        }
                    }
                }
            } catch (_: Exception) {
                // 忽略
            }

            // 检测 TrustManagerFactory 的方法
            try {
                val tmfClass = Class.forName("javax.net.ssl.TrustManagerFactory")
                val initMethod = tmfClass.getDeclaredMethod("init",
                    Class.forName("java.security.KeyStore"))

                // 检查声明类
                if (initMethod.declaringClass != tmfClass) {
                    suspiciousMethods.add("TrustManagerFactory.init (declaring class mismatch)")
                }
            } catch (_: Exception) {
                // 忽略
            }

            // 检测 Application 类的 attach 方法
            try {
                val appClass = context.applicationContext.javaClass
                val methods = appClass.declaredMethods

                for (method in methods) {
                    if (method.name == "attach") {
                        val methodStr = method.toString()
                        if (methodStr.contains("Proxy") || methodStr.contains("xposed") ||
                            methodStr.contains("lsposed", ignoreCase = true)) {
                            suspiciousMethods.add("Application.attach (proxy detected)")
                            break
                        }
                    }
                }
            } catch (_: Exception) {
                // 忽略
            }

            if (suspiciousMethods.isNotEmpty()) {
                return DetectionItem(
                    type = DetectionType.HOOK_LSPOSED,
                    description = "Method hooks detected",
                    isAbnormal = true,
                    details = mapOf(
                        "hooked_methods" to suspiciousMethods.joinToString("; ")
                    )
                )
            }
        } catch (_: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 Xposed 环境变量和系统属性
     */
    private fun checkXposedEnvironment(): DetectionItem? {
        try {
            // 检查环境变量
            val classPath = System.getenv("CLASSPATH")
            if (classPath != null && (classPath.contains("XposedBridge") ||
                classPath.contains("lsposed", ignoreCase = true))) {
                return DetectionItem(
                    type = DetectionType.HOOK_XPOSED,
                    description = "Xposed detected in CLASSPATH",
                    isAbnormal = true,
                    details = mapOf("classpath" to classPath)
                )
            }

            // 检查系统属性（需要通过反射）
            try {
                val systemPropertiesClass = Class.forName("android.os.SystemProperties")
                val getMethod = systemPropertiesClass.getDeclaredMethod("get", String::class.java)
                getMethod.isAccessible = true

                // 检查 ro.dalvik.vm.native.bridge
                val nativeBridge = getMethod.invoke(null, "ro.dalvik.vm.native.bridge") as? String
                if (nativeBridge != null && nativeBridge.isNotEmpty() && nativeBridge != "0") {
                    return DetectionItem(
                        type = DetectionType.HOOK_LSPOSED,
                        description = "Native bridge detected",
                        isAbnormal = true,
                        details = mapOf("native_bridge" to nativeBridge)
                    )
                }
            } catch (_: Exception) {
                // SystemProperties 访问失败，正常情况
            }

            // 检查是否存在 XposedBridge 的资源
            try {
                context.assets.open("xposed_init").close()
                return DetectionItem(
                    type = DetectionType.HOOK_XPOSED,
                    description = "Xposed initialization file found",
                    isAbnormal = true,
                    details = mapOf("file" to "xposed_init")
                )
            } catch (_: Exception) {
                // 预期的异常
            }
        } catch (_: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测异常的异常处理器
     * Xposed 会修改异常处理流程
     */
    private fun checkExceptionHandler(): DetectionItem? {
        try {
            val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
            if (defaultHandler != null) {
                val handlerClass = defaultHandler.javaClass.name
                if (handlerClass.contains("xposed", ignoreCase = true) ||
                    handlerClass.contains("lsposed", ignoreCase = true) ||
                    handlerClass.contains("edxposed", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.HOOK_XPOSED,
                        description = "Xposed exception handler detected",
                        isAbnormal = true,
                        details = mapOf("handler_class" to handlerClass)
                    )
                }
            }
        } catch (_: Exception) {
            // 忽略
        }
        return null
    }
}
