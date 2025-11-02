package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.os.Build
import android.util.Log

/**
 * 非 SDK 接口限制失效检测器
 * 检测应用是否通过某些手段绕过了 Android 的非 SDK 接口限制
 *
 * Android 9+ 引入了对非 SDK 接口的访问限制
 * 如果检测到限制失效，说明环境被篡改（如使用了 FreeReflection、Rik万等工具）
 */
class HiddenApiDetector(private val context: Context) : IDetector {

    companion object {
        private const val TAG = "HiddenApiDetector"
    }

    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 只在 Android 9+ 检测
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return results
        }

        // 1. 尝试访问已知的非 SDK 接口
        checkHiddenApiAccess()?.let { results.add(it) }

        // 2. 检测 FreeReflection
        checkFreeReflection()?.let { results.add(it) }

        // 3. 检测 ReflectUtil/Rik万
        checkReflectUtil()?.let { results.add(it) }

        // 4. 检测元反射绕过
        checkMetaReflectionBypass()?.let { results.add(it) }

        return results
    }

    /**
     * 尝试访问已知的非 SDK 接口
     * 只检测真正被严格限制的黑名单 API
     */
    private fun checkHiddenApiAccess(): DetectionItem? {
        try {
            // 尝试访问一个被严格限制的 API
            // 注意：ActivityThread.currentActivityThread 在某些场景下可以访问，
            // 所以我们使用更严格的 API 进行测试

            // 尝试访问 VMRuntime.setHiddenApiExemptions（这是真正被严格限制的）
            val vmRuntimeClass = Class.forName("dalvik.system.VMRuntime")
            val getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime")
            val vmRuntime = getRuntimeMethod.invoke(null)

            val stringArrayClass = Array<String>::class.java
            val setHiddenApiExemptionsMethod = vmRuntimeClass.getDeclaredMethod(
                "setHiddenApiExemptions",
                stringArrayClass
            )

            // 尝试调用（正常应该失败）
            try {
                setHiddenApiExemptionsMethod.invoke(vmRuntime, arrayOf("L"))
                // 如果成功调用，说明限制被绕过
                return DetectionItem(
                    type = DetectionType.INTEGRITY,
                    description = "Hidden API restrictions bypassed",
                    isAbnormal = true,
                    details = mapOf(
                        "api" to "VMRuntime.setHiddenApiExemptions",
                        "status" to "successfully bypassed"
                    )
                )
            } catch (e: Exception) {
                // 预期的异常，说明限制有效
                Log.d(TAG, "Hidden API access blocked (expected): ${e.message}")
            }
        } catch (e: Exception) {
            // 找不到类或方法
        }
        return null
    }

    /**
     * 检测 FreeReflection 工具
     * FreeReflection 通过修改 VMRuntime 来绕过限制
     */
    private fun checkFreeReflection(): DetectionItem? {
        try {
            // FreeReflection 的典型特征：修改了 VMRuntime 的 hiddenApiExemptions
            val vmRuntimeClass = Class.forName("dalvik.system.VMRuntime")
            val getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime")
            val vmRuntime = getRuntimeMethod.invoke(null)

            // 尝试读取 setHiddenApiExemptions 的调用痕迹
            // 如果能成功调用，说明 FreeReflection 可能已经运行
            // Array<String> 的 Class 对象
            val stringArrayClass = Array<String>::class.java
            val setHiddenApiExemptionsMethod = vmRuntimeClass.getDeclaredMethod(
                "setHiddenApiExemptions",
                stringArrayClass
            )

            if (setHiddenApiExemptionsMethod.isAccessible || !setHiddenApiExemptionsMethod.isAnnotationPresent(java.lang.Deprecated::class.java)) {
                return DetectionItem(
                    type = DetectionType.INTEGRITY,
                    description = "Possible FreeReflection usage detected",
                    isAbnormal = true,
                    details = mapOf(
                        "tool" to "FreeReflection",
                        "method" to "setHiddenApiExemptions accessible"
                    )
                )
            }
        } catch (e: Exception) {
            // 正常情况
        }
        return null
    }

    /**
     * 检测 ReflectUtil/Rik万 等反射增强工具
     * 这些工具通常会在类路径中留下痕迹
     */
    private fun checkReflectUtil(): DetectionItem? {
        val suspiciousClasses = listOf(
            "me.weishu.reflection.Reflection",           // FreeReflection
            "com.swift.sandhook.SandHook",               // SandHook
            "de.robv.android.xposed.XposedHelpers",      // Xposed
            "com.elderdrivers.riru.edxp.util.Hookers"    // EdXposed
        )

        suspiciousClasses.forEach { className ->
            try {
                Class.forName(className)
                return DetectionItem(
                    type = DetectionType.INTEGRITY,
                    description = "Reflection enhancement tool detected",
                    isAbnormal = true,
                    details = mapOf("class" to className)
                )
            } catch (e: ClassNotFoundException) {
                // 预期的异常，继续
            }
        }
        return null
    }

    /**
     * 检测元反射绕过
     * 通过检测是否能访问明确被限制的 API
     */
    private fun checkMetaReflectionBypass(): DetectionItem? {
        try {
            // 尝试访问一个确实被严格限制的 API
            // 使用 VMRuntime.setHiddenApiExemptions 作为测试
            // 这个方法在 Android P+ 被严格限制
            try {
                val vmRuntimeClass = Class.forName("dalvik.system.VMRuntime")
                val getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime")
                val vmRuntime = getRuntimeMethod.invoke(null)

                val stringArrayClass = Array<String>::class.java
                val setHiddenApiExemptionsMethod = vmRuntimeClass.getDeclaredMethod(
                    "setHiddenApiExemptions",
                    stringArrayClass
                )

                // 尝试调用（应该失败）
                try {
                    setHiddenApiExemptionsMethod.invoke(vmRuntime, arrayOf("L"))
                    // 如果成功调用，说明限制被绕过
                    return DetectionItem(
                        type = DetectionType.INTEGRITY,
                        description = "Hidden API restrictions successfully bypassed",
                        isAbnormal = true,
                        details = mapOf(
                            "test_api" to "VMRuntime.setHiddenApiExemptions",
                            "result" to "successfully called"
                        )
                    )
                } catch (e: Exception) {
                    // 预期的异常，说明限制有效
                    Log.d(TAG, "Hidden API enforcement working (expected): ${e.message}")
                }
            } catch (e: Exception) {
                // 找不到类或方法，可能是低版本系统
            }
        } catch (_: Exception) {
            // 忽略
        }
        return null
    }
}