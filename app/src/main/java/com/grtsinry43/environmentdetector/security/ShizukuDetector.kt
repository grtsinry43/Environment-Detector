package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.content.pm.PackageManager
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Shizuku 检测器
 * 检测 Shizuku 服务和相关权限提升工具
 */
class ShizukuDetector(private val context: Context) : IDetector {

    companion object {
        private const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        private const val SHIZUKU_SERVICE_NAME = "shizuku"
    }

    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 1. 检测 Shizuku 包是否安装
        checkShizukuPackage()?.let { results.add(it) }

        // 2. 检测 Shizuku 服务是否运行
        checkShizukuService()?.let { results.add(it) }

        // 3. 检测 Shizuku 权限
        checkShizukuPermission()?.let { results.add(it) }

        // 4. 检测 binder 服务
        checkBinderServices()?.let { results.add(it) }

        return results
    }

    /**
     * 检测 Shizuku 包是否安装
     */
    private fun checkShizukuPackage(): DetectionItem? {
        try {
            context.packageManager.getPackageInfo(SHIZUKU_PACKAGE, 0)
            return DetectionItem(
                type = DetectionType.SHIZUKU,
                description = "Shizuku package installed",
                isAbnormal = true,
                details = mapOf("package" to SHIZUKU_PACKAGE)
            )
        } catch (e: PackageManager.NameNotFoundException) {
            // 未安装，正常
        } catch (e: Exception) {
            // 忽略其他错误
        }
        return null
    }

    /**
     * 检测 Shizuku 服务是否运行
     */
    private fun checkShizukuService(): DetectionItem? {
        try {
            // 检测服务进程
            val psProcess = Runtime.getRuntime().exec("ps -A")
            val reader = BufferedReader(InputStreamReader(psProcess.inputStream))
            val processOutput = reader.readText()
            reader.close()
            psProcess.waitFor()

            if (processOutput.contains(SHIZUKU_SERVICE_NAME, ignoreCase = true)) {
                return DetectionItem(
                    type = DetectionType.SHIZUKU,
                    description = "Shizuku service is running",
                    isAbnormal = true,
                    details = mapOf("service" to SHIZUKU_SERVICE_NAME)
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 Shizuku 权限
     */
    private fun checkShizukuPermission(): DetectionItem? {
        try {
            val permission = "moe.shizuku.manager.permission.API_V23"
            val result = context.checkCallingOrSelfPermission(permission)
            if (result == PackageManager.PERMISSION_GRANTED) {
                return DetectionItem(
                    type = DetectionType.SHIZUKU,
                    description = "Shizuku permission granted",
                    isAbnormal = true,
                    details = mapOf("permission" to permission)
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 Binder 服务中的 Shizuku
     */
    private fun checkBinderServices(): DetectionItem? {
        try {
            val serviceCheckProcess = Runtime.getRuntime().exec("service list")
            val reader = BufferedReader(InputStreamReader(serviceCheckProcess.inputStream))
            val serviceList = reader.readText()
            reader.close()
            serviceCheckProcess.waitFor()

            if (serviceList.contains("shizuku", ignoreCase = true)) {
                return DetectionItem(
                    type = DetectionType.SHIZUKU,
                    description = "Shizuku binder service detected",
                    isAbnormal = true,
                    details = mapOf("source" to "service list")
                )
            }
        } catch (e: Exception) {
            // service list 命令可能不可用
        }
        return null
    }
}
