package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * 开发者选项检测器
 * 检测开发者模式、ADB 调试、USB 调试等
 */
class DeveloperOptionsDetector(private val context: Context) : IDetector {

    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 1. 检测开发者选项是否开启
        checkDeveloperOptions()?.let { results.add(it) }

        // 2. 检测 ADB 是否启用
        checkAdbEnabled()?.let { results.add(it) }

        // 3. 检测应用是否可调试
        checkDebuggable()?.let { results.add(it) }

        // 4. 检测是否连接了调试器
        checkDebuggerConnected()?.let { results.add(it) }

        // 5. 检测 ADB TCP 端口
        checkAdbTcpPort()?.let { results.add(it) }

        return results
    }

    /**
     * 检测开发者选项是否开启
     */
    private fun checkDeveloperOptions(): DetectionItem? {
        try {
            val developerMode = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            )

            if (developerMode == 1) {
                return DetectionItem(
                    type = DetectionType.DEVELOPER_OPTIONS,
                    description = "Developer options are enabled",
                    isAbnormal = true,
                    details = mapOf("enabled" to "true")
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 ADB 是否启用
     */
    private fun checkAdbEnabled(): DetectionItem? {
        try {
            val adbEnabled = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED,
                0
            )

            if (adbEnabled == 1) {
                return DetectionItem(
                    type = DetectionType.ADB_ENABLED,
                    description = "ADB debugging is enabled",
                    isAbnormal = true,
                    details = mapOf("enabled" to "true")
                )
            }
        } catch (e: Exception) {
            // 某些 ROM 可能限制访问
        }
        return null
    }

    /**
     * 检测应用是否可调试
     */
    private fun checkDebuggable(): DetectionItem? {
        try {
            val isDebuggable = (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

            if (isDebuggable) {
                return DetectionItem(
                    type = DetectionType.DEBUGGABLE,
                    description = "Application is debuggable",
                    isAbnormal = true,
                    details = mapOf("debuggable" to "true")
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测是否连接了调试器
     */
    private fun checkDebuggerConnected(): DetectionItem? {
        try {
            if (android.os.Debug.isDebuggerConnected()) {
                return DetectionItem(
                    type = DetectionType.DEBUGGABLE,
                    description = "Debugger is currently connected",
                    isAbnormal = true,
                    details = mapOf("debugger_connected" to "true")
                )
            }

            // 检测 TracerPid（被调试时不为 0）
            val statusFile = java.io.File("/proc/self/status")
            if (statusFile.exists()) {
                val content = statusFile.readText()
                val tracerPidLine = content.split("\n").find { it.startsWith("TracerPid:") }
                if (tracerPidLine != null) {
                    val tracerPid = tracerPidLine.substringAfter(":").trim().toIntOrNull()
                    if (tracerPid != null && tracerPid != 0) {
                        return DetectionItem(
                            type = DetectionType.DEBUGGABLE,
                            description = "Process is being traced",
                            isAbnormal = true,
                            details = mapOf("tracer_pid" to tracerPid.toString())
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
     * 检测 ADB TCP 端口
     */
    private fun checkAdbTcpPort(): DetectionItem? {
        try {
            // 检测 ADB over TCP
            val netstatProcess = Runtime.getRuntime().exec("netstat -anp")
            val reader = BufferedReader(InputStreamReader(netstatProcess.inputStream))
            val netstatOutput = reader.readText()
            reader.close()
            netstatProcess.waitFor()

            // ADB 默认 TCP 端口是 5555
            if (netstatOutput.contains(":5555")) {
                return DetectionItem(
                    type = DetectionType.ADB_ENABLED,
                    description = "ADB over TCP is active",
                    isAbnormal = true,
                    details = mapOf("port" to "5555")
                )
            }
        } catch (e: Exception) {
            // netstat 可能不可用
        }
        return null
    }
}
