package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.util.Log

/**
 * Native 层安全检测器
 * 使用 JNI 执行更深层次的安全检测，难以被 Hook
 */
class NativeSecurityDetector {

    companion object {
        private const val TAG = "NativeSecurityDetector"
        private var isNativeLibraryLoaded = false
        private var isInitialized = false

        init {
            try {
                System.loadLibrary("security_native")
                isNativeLibraryLoaded = true
                Log.d(TAG, "Native security library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native security library", e)
                isNativeLibraryLoaded = false
            }
        }

        /**
         * Native Root 检测
         * 检测：su 二进制、系统属性、危险权限
         */
        @JvmStatic
        external fun nativeCheckRoot(): Boolean

        /**
         * Native Hook 检测
         * 检测：已加载的库、Frida 端口、LD_PRELOAD
         */
        @JvmStatic
        external fun nativeCheckHook(): Boolean

        /**
         * Native 调试器检测
         * 检测：TracerPid、ptrace、异常 FD
         */
        @JvmStatic
        external fun nativeCheckDebugger(): Boolean

        /**
         * Native 模拟器检测
         * 检测：CPU 特征、QEMU 文件
         */
        @JvmStatic
        external fun nativeCheckEmulator(): Boolean

        /**
         * 初始化反 Hook 保护
         * 必须在检测前调用
         */
        @JvmStatic
        external fun initAntiHook(context: Context)

        /**
         * 初始化（内部使用）
         */
        internal fun initialize(context: Context) {
            if (!isNativeLibraryLoaded || isInitialized) {
                return
            }
            try {
                initAntiHook(context)
                isInitialized = true
                Log.d(TAG, "Anti-hook protection initialized")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize anti-hook protection", e)
            }
        }
    }

    /**
     * 执行 Native 层检测
     */
    fun performNativeDetection(context: Context): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        if (!isNativeLibraryLoaded) {
            Log.w(TAG, "Native library not loaded, skipping native detection")
            return results
        }

        // 初始化反 Hook 保护
        initialize(context)

        try {
            // Root 检测
            if (nativeCheckRoot()) {
                results.add(
                    DetectionItem(
                        type = DetectionType.ROOT,
                        description = "Root detected by native layer",
                        isAbnormal = true,
                        details = mapOf("source" to "native")
                    )
                )
            }

            // Hook 检测
            if (nativeCheckHook()) {
                results.add(
                    DetectionItem(
                        type = DetectionType.HOOK_FRIDA,
                        description = "Hook framework detected by native layer",
                        isAbnormal = true,
                        details = mapOf("source" to "native")
                    )
                )
            }

            // 调试器检测
            if (nativeCheckDebugger()) {
                results.add(
                    DetectionItem(
                        type = DetectionType.DEBUGGABLE,
                        description = "Debugger detected by native layer",
                        isAbnormal = true,
                        details = mapOf("source" to "native")
                    )
                )
            }

            // 模拟器检测
            if (nativeCheckEmulator()) {
                results.add(
                    DetectionItem(
                        type = DetectionType.EMULATOR,
                        description = "Emulator detected by native layer",
                        isAbnormal = true,
                        details = mapOf("source" to "native")
                    )
                )
            }

            Log.d(TAG, "Native detection completed: ${results.size} issues found")
        } catch (e: Exception) {
            Log.e(TAG, "Native detection error", e)
            results.add(
                DetectionItem(
                    type = DetectionType.ERROR,
                    description = "Native detection error: ${e.message}",
                    isAbnormal = true,
                    details = mapOf("error" to e.message.orEmpty())
                )
            )
        }

        return results
    }
}
