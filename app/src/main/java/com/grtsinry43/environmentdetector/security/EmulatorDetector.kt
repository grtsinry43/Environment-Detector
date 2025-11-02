package com.grtsinry43.environmentdetector.security

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import androidx.annotation.RequiresPermission
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * 模拟器/虚拟机检测器
 * 通过硬件特征、CPU 信息、传感器等多维度检测
 */
class EmulatorDetector(private val context: Context) : IDetector {

    companion object {
        // 已知的模拟器特征值
        private val KNOWN_EMULATOR_MANUFACTURERS = setOf("Genymotion", "unknown", "Google", "Android")
        private val KNOWN_EMULATOR_MODELS = setOf(
            "sdk", "google_sdk", "emulator", "Android SDK built for x86",
            "Genymotion", "vbox86p", "Droid4X"
        )
        private val KNOWN_EMULATOR_BOARDS = setOf("unknown", "goldfish")
        private val KNOWN_EMULATOR_BRANDS = setOf("generic", "generic_x86", "TTVM", "google")
        private val KNOWN_EMULATOR_DEVICES = setOf("generic", "generic_x86", "vbox86p")
        private val KNOWN_EMULATOR_PRODUCTS = setOf("sdk", "google_sdk", "sdk_x86", "vbox86p")
    }

    @RequiresPermission("android.permission.READ_PRIVILEGED_PHONE_STATE")
    override suspend fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()

        // 1. 基础硬件信息检测
        checkBasicHardwareInfo()?.let { results.add(it) }

        // 2. CPU 特征检测
        checkCpuInfo()?.let { results.add(it) }

        // 3. 传感器检测
        checkSensors()?.let { results.add(it) }

        // 4. 电话功能检测
        checkTelephonyFeatures()?.let { results.add(it) }

        // 5. 系统属性组合检测
        checkSystemPropertiesCombination()?.let { results.add(it) }

        // 6. 检测已知的模拟器进程
        checkEmulatorProcesses()?.let { results.add(it) }

        // 7. 检测 QEMU 特征
        checkQemuDrivers()?.let { results.add(it) }

        // 8. 检测设备 ID 特征
        checkDeviceIds()?.let { results.add(it) }

        return results
    }

    /**
     * 检测基础硬件信息
     */
    private fun checkBasicHardwareInfo(): DetectionItem? {
        val suspiciousFeatures = mutableListOf<String>()

        // 检测制造商
        if (Build.MANUFACTURER.lowercase() in KNOWN_EMULATOR_MANUFACTURERS.map { it.lowercase() }) {
            suspiciousFeatures.add("manufacturer:${Build.MANUFACTURER}")
        }

        // 检测模型
        if (Build.MODEL.lowercase() in KNOWN_EMULATOR_MODELS.map { it.lowercase() } ||
            Build.MODEL.contains("sdk", ignoreCase = true) ||
            Build.MODEL.contains("emulator", ignoreCase = true)) {
            suspiciousFeatures.add("model:${Build.MODEL}")
        }

        // 检测板型
        if (Build.BOARD.lowercase() in KNOWN_EMULATOR_BOARDS.map { it.lowercase() }) {
            suspiciousFeatures.add("board:${Build.BOARD}")
        }

        // 检测品牌
        if (Build.BRAND.lowercase() in KNOWN_EMULATOR_BRANDS.map { it.lowercase() }) {
            suspiciousFeatures.add("brand:${Build.BRAND}")
        }

        // 检测设备
        if (Build.DEVICE.lowercase() in KNOWN_EMULATOR_DEVICES.map { it.lowercase() }) {
            suspiciousFeatures.add("device:${Build.DEVICE}")
        }

        // 检测产品
        if (Build.PRODUCT.lowercase() in KNOWN_EMULATOR_PRODUCTS.map { it.lowercase() }) {
            suspiciousFeatures.add("product:${Build.PRODUCT}")
        }

        // 需要多个特征匹配才判定为模拟器（避免误报）
        if (suspiciousFeatures.size >= 3) {
            return DetectionItem(
                type = DetectionType.EMULATOR,
                description = "Multiple emulator hardware characteristics detected",
                isAbnormal = true,
                details = mapOf(
                    "suspicious_count" to suspiciousFeatures.size.toString(),
                    "features" to suspiciousFeatures.joinToString(", ")
                )
            )
        }

        return null
    }

    /**
     * 检测 CPU 信息
     */
    private fun checkCpuInfo(): DetectionItem? {
        try {
            val cpuInfoFile = File("/proc/cpuinfo")
            if (cpuInfoFile.exists()) {
                val cpuInfo = cpuInfoFile.readText()

                // 检测 x86 架构（大多数真实设备是 ARM）
                if (cpuInfo.contains("Intel", ignoreCase = true) ||
                    cpuInfo.contains("AMD", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.EMULATOR,
                        description = "X86 CPU architecture detected (expected ARM)",
                        isAbnormal = true,
                        details = mapOf(
                            "source" to "/proc/cpuinfo",
                            "architecture" to if (cpuInfo.contains("Intel")) "Intel" else "AMD"
                        )
                    )
                }

                // 检测 QEMU 特征
                if (cpuInfo.contains("goldfish", ignoreCase = true) ||
                    cpuInfo.contains("qemu", ignoreCase = true) ||
                    cpuInfo.contains("vbox", ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.EMULATOR,
                        description = "Emulator signature in CPU info",
                        isAbnormal = true,
                        details = mapOf("source" to "/proc/cpuinfo")
                    )
                }

                // 检测处理器数量异常（模拟器通常只有 1-2 个核心）
                val processorCount = cpuInfo.split("\n")
                    .count { it.startsWith("processor", ignoreCase = true) }
                if (processorCount == 1) {
                    // 现代真实设备很少单核
                    return DetectionItem(
                        type = DetectionType.EMULATOR,
                        description = "Single-core processor detected",
                        isAbnormal = true,
                        details = mapOf("processor_count" to "1")
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测传感器
     * 模拟器通常缺少真实设备的传感器
     */
    private fun checkSensors(): DetectionItem? {
        try {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val sensorList = sensorManager.getSensorList(Sensor.TYPE_ALL)

            // 检查关键传感器
            val hasAccelerometer = sensorList.any { it.type == Sensor.TYPE_ACCELEROMETER }
            val hasGyroscope = sensorList.any { it.type == Sensor.TYPE_GYROSCOPE }
            val hasMagnetometer = sensorList.any { it.type == Sensor.TYPE_MAGNETIC_FIELD }
            val hasProximity = sensorList.any { it.type == Sensor.TYPE_PROXIMITY }
            val hasLight = sensorList.any { it.type == Sensor.TYPE_LIGHT }

            val missingSensors = mutableListOf<String>()
            if (!hasAccelerometer) missingSensors.add("Accelerometer")
            if (!hasGyroscope) missingSensors.add("Gyroscope")
            if (!hasMagnetometer) missingSensors.add("Magnetometer")
            if (!hasProximity) missingSensors.add("Proximity")
            if (!hasLight) missingSensors.add("Light")

            // 如果缺少 3 个以上关键传感器，很可能是模拟器
            if (missingSensors.size >= 3) {
                return DetectionItem(
                    type = DetectionType.EMULATOR,
                    description = "Multiple critical sensors missing",
                    isAbnormal = true,
                    details = mapOf(
                        "missing_sensors" to missingSensors.joinToString(", "),
                        "total_sensors" to sensorList.size.toString()
                    )
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测电话功能
     */
    @RequiresPermission("android.permission.READ_PRIVILEGED_PHONE_STATE")
    private fun checkTelephonyFeatures(): DetectionItem? {
        try {
            val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            // 检测设备 ID（IMEI）
            // 模拟器通常返回全 0 或固定值
            try {
                @Suppress("DEPRECATION")
                val deviceId = telephonyManager.deviceId
                if (deviceId != null) {
                    // 检测是否为已知的模拟器 IMEI
                    val knownEmulatorImeis = setOf(
                        "000000000000000",
                        "004999010640000",
                        "012345678912345"
                    )
                    if (deviceId in knownEmulatorImeis || deviceId.all { it == '0' }) {
                        return DetectionItem(
                            type = DetectionType.EMULATOR,
                            description = "Known emulator device ID detected",
                            isAbnormal = true,
                            details = mapOf("device_id_pattern" to "emulator_pattern")
                        )
                    }
                }
            } catch (e: Exception) {
                // Android 10+ 需要特殊权限
            }

            // 检测运营商
            val networkOperator = telephonyManager.networkOperator
            if (networkOperator == "310260") { // Android 模拟器默认运营商
                return DetectionItem(
                    type = DetectionType.EMULATOR,
                    description = "Default emulator network operator detected",
                    isAbnormal = true,
                    details = mapOf("network_operator" to (networkOperator ?: "310260"))
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测系统属性组合
     */
    private fun checkSystemPropertiesCombination(): DetectionItem? {
        try {
            // 使用 getprop 获取系统属性
            val qemuProp = getSystemProperty("ro.kernel.qemu")
            val hardwareProp = getSystemProperty("ro.hardware")
            val productBoardProp = getSystemProperty("ro.product.board")

            val suspiciousProps = mutableListOf<String>()

            if (qemuProp == "1") {
                suspiciousProps.add("ro.kernel.qemu=1")
            }

            if (hardwareProp?.contains("goldfish", ignoreCase = true) == true ||
                hardwareProp?.contains("ranchu", ignoreCase = true) == true ||
                hardwareProp?.contains("vbox", ignoreCase = true) == true) {
                suspiciousProps.add("ro.hardware=$hardwareProp")
            }

            if (productBoardProp?.contains("goldfish", ignoreCase = true) == true) {
                suspiciousProps.add("ro.product.board=$productBoardProp")
            }

            if (suspiciousProps.isNotEmpty()) {
                return DetectionItem(
                    type = DetectionType.EMULATOR,
                    description = "Emulator system properties detected",
                    isAbnormal = true,
                    details = mapOf("properties" to suspiciousProps.joinToString(", "))
                )
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测模拟器进程
     */
    private fun checkEmulatorProcesses(): DetectionItem? {
        try {
            val emulatorProcessNames = listOf(
                "qemu-system",
                "qemu",
                "vboxsf",
                "genymotion",
                "nox",
                "bluestacks"
            )

            val psProcess = Runtime.getRuntime().exec("ps")
            val reader = BufferedReader(InputStreamReader(psProcess.inputStream))
            val processOutput = reader.readText()
            reader.close()
            psProcess.waitFor()

            emulatorProcessNames.forEach { processName ->
                if (processOutput.contains(processName, ignoreCase = true)) {
                    return DetectionItem(
                        type = DetectionType.EMULATOR,
                        description = "Emulator process detected",
                        isAbnormal = true,
                        details = mapOf("process_name" to processName)
                    )
                }
            }
        } catch (e: Exception) {
            // ps 命令可能不可用
        }
        return null
    }

    /**
     * 检测 QEMU 驱动
     */
    private fun checkQemuDrivers(): DetectionItem? {
        try {
            val qemuDrivers = listOf(
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so"
            )

            qemuDrivers.forEach { driver ->
                if (File(driver).exists()) {
                    return DetectionItem(
                        type = DetectionType.EMULATOR,
                        description = "QEMU driver file detected",
                        isAbnormal = true,
                        details = mapOf("driver_path" to driver)
                    )
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return null
    }

    /**
     * 检测设备 ID 特征
     */
    private fun checkDeviceIds(): DetectionItem? {
        try {
            @Suppress("DEPRECATION")
            val androidId = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            )

            // 模拟器通常返回固定的 Android ID
            if (androidId == "9774d56d682e549c") { // 已知的模拟器 Android ID
                return DetectionItem(
                    type = DetectionType.EMULATOR,
                    description = "Known emulator Android ID detected",
                    isAbnormal = true,
                    details = mapOf("android_id" to (androidId ?: "9774d56d682e549c"))
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
