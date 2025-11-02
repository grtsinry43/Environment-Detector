package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 环境安全检测器 - 主入口
 * 采用业界最佳实践，深度检测设备环境安全性
 */
class EnvironmentDetector(private val context: Context) {

    companion object {
        private const val TAG = "EnvironmentDetector"
        @Volatile
        private var instance: EnvironmentDetector? = null

        fun getInstance(context: Context): EnvironmentDetector {
            return instance ?: synchronized(this) {
                instance ?: EnvironmentDetector(context.applicationContext).also { instance = it }
            }
        }
    }

    // 检测器列表
    private val detectors = listOf(
        RootDetector(context),
        HookDetector(context),
        ShizukuDetector(context),
        DeveloperOptionsDetector(context),
        EmulatorDetector(context),
        IntegrityDetector(context),
        HiddenApiDetector(context)
    )

    private val nativeDetector = NativeSecurityDetector()

    /**
     * 执行全面的环境检测
     */
    suspend fun performFullDetection(): DetectionResult {
        return withContext(Dispatchers.IO) {
            val results = mutableListOf<DetectionItem>()
            val startTime = System.currentTimeMillis()

            Log.d(TAG, "Starting environment detection...")

            // 执行 Java 层检测
            detectors.forEach { detector ->
                try {
                    val detectorResults = detector.detect()
                    results.addAll(detectorResults)

                    // 记录每个检测器的结果
                    detectorResults.forEach { item ->
                        if (item.isAbnormal) {
                            Log.w(TAG, "Abnormal environment detected: ${item.type} - ${item.description}")
                            Log.d(TAG, "Details: ${item.details}")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error in detector ${detector.javaClass.simpleName}", e)
                    results.add(
                        DetectionItem(
                            type = DetectionType.ERROR,
                            description = "Detection error: ${detector.javaClass.simpleName}",
                            isAbnormal = true,
                            details = mapOf("error" to e.message.orEmpty())
                        )
                    )
                }
            }

            // 执行 Native 层检测
            try {
                val nativeResults = nativeDetector.performNativeDetection(context)
                results.addAll(nativeResults)
            } catch (e: Exception) {
                Log.e(TAG, "Native detection failed", e)
            }

            val endTime = System.currentTimeMillis()
            val isEnvironmentClean = results.none { it.isAbnormal }

            Log.d(TAG, "Detection completed in ${endTime - startTime}ms")
            Log.d(TAG, "Environment clean: $isEnvironmentClean")

            DetectionResult(
                isClean = isEnvironmentClean,
                detectionItems = results,
                timestamp = System.currentTimeMillis(),
                detectionTimeMs = endTime - startTime
            )
        }
    }

    /**
     * 快速检测（只执行关键项目）
     */
    suspend fun performQuickDetection(): DetectionResult {
        return withContext(Dispatchers.IO) {
            val results = mutableListOf<DetectionItem>()

            // 只执行最关键的检测
            val criticalDetectors = listOf(
                RootDetector(context),
                HookDetector(context)
            )

            criticalDetectors.forEach { detector ->
                try {
                    results.addAll(detector.detect())
                } catch (e: Exception) {
                    Log.e(TAG, "Quick detection error", e)
                }
            }

            DetectionResult(
                isClean = results.none { it.isAbnormal },
                detectionItems = results,
                timestamp = System.currentTimeMillis(),
                detectionTimeMs = 0
            )
        }
    }
}

/**
 * 检测结果
 */
data class DetectionResult(
    val isClean: Boolean,
    val detectionItems: List<DetectionItem>,
    val timestamp: Long,
    val detectionTimeMs: Long
) {
    fun toLogString(): String {
        return buildString {
            appendLine("=== Environment Detection Report ===")
            appendLine("Time: ${java.util.Date(timestamp)}")
            appendLine("Duration: ${detectionTimeMs}ms")
            appendLine("Environment Clean: $isClean")
            appendLine("Detection Items:")
            detectionItems.forEach { item ->
                appendLine("  - ${item.type}: ${item.description}")
                if (item.isAbnormal) {
                    item.details.forEach { (key, value) ->
                        appendLine("    * $key: $value")
                    }
                }
            }
            appendLine("=================================")
        }
    }
}

/**
 * 单个检测项
 */
data class DetectionItem(
    val type: DetectionType,
    val description: String,
    val isAbnormal: Boolean,
    val details: Map<String, String> = emptyMap()
)

/**
 * 检测类型枚举
 */
enum class DetectionType {
    ROOT,
    HOOK_XPOSED,
    HOOK_LSPOSED,
    HOOK_RIRU,
    HOOK_ZYGISK,
    HOOK_SUBSTRATE,
    HOOK_FRIDA,
    SHIZUKU,
    DEVELOPER_OPTIONS,
    ADB_ENABLED,
    EMULATOR,
    VIRTUAL_MACHINE,
    PACKAGE_INSTALLER,
    SIGNATURE,
    DEBUGGABLE,
    INTEGRITY,
    ERROR
}

/**
 * 检测器基础接口
 */
interface IDetector {
    suspend fun detect(): List<DetectionItem>
}