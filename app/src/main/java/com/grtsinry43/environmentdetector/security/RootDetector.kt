package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Root 检测器
 * 使用多种深度检测方法，避免简单的文件/包名检测
 */
class RootDetector(private val context: Context) : IDetector {

    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 1. SELinux 状态检测
        checkSELinuxStatus()?.let { results.add(it) }

        // 2. 系统属性检测
        checkSystemProperties()?.let { results.add(it) }

        // 3. Mount 分析（检测系统分区是否可写）
        checkMountStatus()?.let { results.add(it) }

        // 4. Su 二进制深度验证
        checkSuBinary()?.let { results.add(it) }

        // 5. Build Tags 检测
        checkBuildTags()?.let { results.add(it) }

        // 6. 检测危险目录权限
        checkDangerousDirectoryPermissions()?.let { results.add(it) }

        // 7. 检测系统分区修改痕迹
        checkSystemModification()?.let { results.add(it) }

        // 8. Magisk 特征检测（通过行为而非文件）
        checkMagiskBehavior()?.let { results.add(it) }

        return results
    }

    /**
     * 检测 SELinux 状态
     * Root 后通常会将 SELinux 设置为 Permissive 或关闭
     */
    private fun checkSELinuxStatus(): DetectionItem? {
        try {
            val process = Runtime.getRuntime().exec("getenforce")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()?.trim()
            reader.close()
            process.waitFor()

            if (result.equals("Permissive", ignoreCase = true)) {
                return DetectionItem(
                    type = DetectionType.ROOT,
                    description = "SELinux is in Permissive mode",
                    isAbnormal = true,
                    details = mapOf("selinux_status" to (result ?: "Permissive"))
                )
            }
        } catch (e: Exception) {
            // getenforce 命令失败可能也是异常情况
        }
        return null
    }

    /**
     * 检测关键系统属性
     */
    private fun checkSystemProperties(): DetectionItem? {
        try {
            // ro.debuggable 应该为 0
            val debuggable = getSystemProperty("ro.debuggable")
            if (debuggable == "1") {
                return DetectionItem(
                    type = DetectionType.ROOT,
                    description = "System is debuggable (ro.debuggable=1)",
                    isAbnormal = true,
                    details = mapOf("ro.debuggable" to "1")
                )
            }

            // ro.secure 应该为 1
            val secure = getSystemProperty("ro.secure")
            if (secure == "0") {
                return DetectionItem(
                    type = DetectionType.ROOT,
                    description = "System is not secure (ro.secure=0)",
                    isAbnormal = true,
                    details = mapOf("ro.secure" to "0")
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 分析 mount 命令输出，检测系统分区是否以 rw 方式挂载
     */
    private fun checkMountStatus(): DetectionItem? {
        try {
            val process = Runtime.getRuntime().exec("mount")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val mountInfo = reader.readLines()
            reader.close()
            process.waitFor()

            val suspiciousMounts = mutableListOf<String>()

            // 检测关键分区是否以 rw 挂载
            val criticalPartitions = listOf("/system", "/vendor", "/product")
            mountInfo.forEach { line ->
                criticalPartitions.forEach { partition ->
                    if (line.contains(partition) && line.contains(" rw,") || line.contains(" rw ")) {
                        suspiciousMounts.add(line)
                    }
                }
            }

            if (suspiciousMounts.isNotEmpty()) {
                return DetectionItem(
                    type = DetectionType.ROOT,
                    description = "Critical partitions mounted as read-write",
                    isAbnormal = true,
                    details = mapOf(
                        "suspicious_mounts" to suspiciousMounts.joinToString("; "),
                        "count" to suspiciousMounts.size.toString()
                    )
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * Su 二进制深度验证
     * 不仅检测文件存在，还尝试执行并验证响应
     */
    private fun checkSuBinary(): DetectionItem? {
        try {
            // 尝试执行 which su
            val whichProcess = Runtime.getRuntime().exec("which su")
            val whichReader = BufferedReader(InputStreamReader(whichProcess.inputStream))
            val suPath = whichReader.readLine()
            whichReader.close()
            whichProcess.waitFor()

            if (!suPath.isNullOrBlank()) {
                // 找到了 su，尝试验证
                try {
                    val testProcess = Runtime.getRuntime().exec(arrayOf("su", "-v"))
                    val testReader = BufferedReader(InputStreamReader(testProcess.inputStream))
                    val version = testReader.readLine()
                    testReader.close()
                    testProcess.waitFor()

                    return DetectionItem(
                        type = DetectionType.ROOT,
                        description = "Su binary is functional",
                        isAbnormal = true,
                        details = mapOf(
                            "su_path" to (suPath ?: "unknown"),
                            "su_version" to (version ?: "unknown")
                        )
                    )
                } catch (e: Exception) {
                    // 即使执行失败，找到 su 就是问题
                    return DetectionItem(
                        type = DetectionType.ROOT,
                        description = "Su binary found in system",
                        isAbnormal = true,
                        details = mapOf("su_path" to (suPath ?: "unknown"))
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测 Build Tags
     * 非官方构建通常会有 test-keys 标签
     */
    private fun checkBuildTags(): DetectionItem? {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) {
            return DetectionItem(
                type = DetectionType.ROOT,
                description = "System built with test-keys",
                isAbnormal = true,
                details = mapOf("build_tags" to tags)
            )
        }
        return null
    }

    /**
     * 检测危险目录权限
     * Root 后某些系统目录的权限可能被修改
     */
    private fun checkDangerousDirectoryPermissions(): DetectionItem? {
        try {
            val dangerousPaths = listOf(
                "/data",
                "/system/bin",
                "/system/xbin",
                "/system/app"
            )

            val accessiblePaths = mutableListOf<String>()

            dangerousPaths.forEach { path ->
                val file = File(path)
                // 尝试列出目录（正常情况下应该无权限）
                if (file.canWrite()) {
                    accessiblePaths.add(path)
                }
            }

            if (accessiblePaths.isNotEmpty()) {
                return DetectionItem(
                    type = DetectionType.ROOT,
                    description = "Suspicious write access to system directories",
                    isAbnormal = true,
                    details = mapOf(
                        "writable_paths" to accessiblePaths.joinToString(", ")
                    )
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测系统分区修改痕迹
     */
    private fun checkSystemModification(): DetectionItem? {
        try {
            // 检测非标准的可疑文件或目录
            val suspiciousFiles = listOf(
                "/system/app/Superuser.apk",
                "/system/bin/busybox"
            )

            suspiciousFiles.forEach { path ->
                val file = File(path)
                if (file.exists()) {
                    return DetectionItem(
                        type = DetectionType.ROOT,
                        description = "Suspicious system modification detected",
                        isAbnormal = true,
                        details = mapOf("suspicious_file" to path)
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * Magisk 行为检测
     * 通过检测 Magisk 的行为特征而非文件
     */
    private fun checkMagiskBehavior(): DetectionItem? {
        try {
            // Magisk 会修改 mount namespace
            val process = Runtime.getRuntime().exec("cat /proc/self/mountinfo")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val mountInfo = reader.readText()
            reader.close()
            process.waitFor()

            // Magisk 的典型特征：大量的 bind mount
            val bindMountCount = mountInfo.split("\n").count { it.contains("bind") }
            if (bindMountCount > 50) { // 正常设备通常少于 20 个
                return DetectionItem(
                    type = DetectionType.ROOT,
                    description = "Abnormal mount namespace detected",
                    isAbnormal = true,
                    details = mapOf(
                        "bind_mount_count" to bindMountCount.toString(),
                        "threshold" to "50"
                    )
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 获取系统属性
     */
    private fun getSystemProperty(key: String): String? {
        try {
            val process = Runtime.getRuntime().exec("getprop $key")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim()
            reader.close()
            process.waitFor()
            return value
        } catch (e: Exception) {
            return null
        }
    }
}
