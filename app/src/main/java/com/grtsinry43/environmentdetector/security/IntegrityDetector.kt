package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * 完整性检测器
 * 检测应用签名、安装来源、DEX 完整性等
 */
class IntegrityDetector(private val context: Context) : IDetector {

    companion object {
        // 预期的应用签名（需要在发布时配置）
        // 这里是示例值，实际使用时需要替换为真实的签名哈希
        private const val EXPECTED_SIGNATURE_HASH = "YOUR_RELEASE_SIGNATURE_SHA256"

        // 可信的安装来源
        private val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",      // Google Play Store
            "com.google.android.feedback", // Google Play Store (alternative)
            "com.android.packageinstaller" // 系统安装器（可选）
        )
    }

    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 1. 检测应用签名
        checkSignature()?.let { results.add(it) }

        // 2. 检测安装来源
        checkInstaller()?.let { results.add(it) }

        // 3. 检测是否从外部存储安装
        checkInstallLocation()?.let { results.add(it) }

        // 移除重新打包检测，因为正常的应用更新、调试重装都会导致误报
        // checkRepackaging()?.let { results.add(it) }

        return results
    }

    /**
     * 检测应用签名
     */
    private fun checkSignature(): DetectionItem? {
        try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures != null && signatures.isNotEmpty()) {
                val signature = signatures[0]
                val signatureHash = getSignatureHash(signature)

                // 在开发阶段，我们只记录签名而不判定为异常
                // 生产环境应该验证签名是否匹配预期值
                if (EXPECTED_SIGNATURE_HASH != "YOUR_RELEASE_SIGNATURE_SHA256" &&
                    signatureHash != EXPECTED_SIGNATURE_HASH) {
                    return DetectionItem(
                        type = DetectionType.SIGNATURE,
                        description = "Application signature mismatch",
                        isAbnormal = true,
                        details = mapOf(
                            "current_hash" to signatureHash,
                            "expected_hash" to EXPECTED_SIGNATURE_HASH
                        )
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测安装来源
     * 注意：对于开发和测试阶段，这只是信息提示，不标记为异常
     */
    private fun checkInstaller(): DetectionItem? {
        try {
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }

            // 如果没有安装来源（调试安装或侧载）
            if (installer == null) {
                return DetectionItem(
                    type = DetectionType.PACKAGE_INSTALLER,
                    description = "No installer package (Debug or sideload install)",
                    isAbnormal = false,  // 改为 false，仅作为信息提示
                    details = mapOf("installer" to "null", "note" to "This is normal for development builds")
                )
            }

            // 如果来源不在可信列表中，但不标记为异常
            if (installer !in TRUSTED_INSTALLERS) {
                return DetectionItem(
                    type = DetectionType.PACKAGE_INSTALLER,
                    description = "Application installed from: $installer",
                    isAbnormal = false,  // 改为 false，仅作为信息提示
                    details = mapOf("installer" to installer)
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测安装位置
     */
    private fun checkInstallLocation(): DetectionItem? {
        try {
            val sourceDir = context.applicationInfo.sourceDir

            // 检测是否安装在外部存储（不安全）
            if (sourceDir.contains("/mnt/") || sourceDir.contains("/sdcard/")) {
                return DetectionItem(
                    type = DetectionType.INTEGRITY,
                    description = "Application installed on external storage",
                    isAbnormal = true,
                    details = mapOf("source_dir" to sourceDir)
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 获取签名的 SHA-256 哈希
     */
    private fun getSignatureHash(signature: Signature): String {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(signature.toByteArray())
            return digest.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            return ""
        }
    }
}
