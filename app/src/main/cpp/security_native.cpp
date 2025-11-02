#include <jni.h>
#include <string>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dirent.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/system_properties.h>

#define LOG_TAG "SecurityNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 外部声明反 Hook 验证函数
extern bool verifyNativeCall(JNIEnv* env);

/**
 * 反调试：检测 TracerPid
 */
bool checkTracerPid() {
    std::ifstream statusFile("/proc/self/status");
    if (!statusFile.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.find("TracerPid:") == 0) {
            int tracerPid = std::stoi(line.substr(10));
            if (tracerPid != 0) {
                LOGW("TracerPid detected: %d", tracerPid);
                return true;
            }
            break;
        }
    }
    return false;
}

/**
 * 反调试：尝试 ptrace 自己
 * 注意：这个检测可能会误报，因为某些系统限制导致 ptrace 失败
 * 我们需要更谨慎地判断
 */
bool checkPtraceAttach() {
    // 首先检查 TracerPid，如果已经有 tracer，才认为是被调试
    if (!checkTracerPid()) {
        // 没有 TracerPid，即使 ptrace 失败也不一定是被调试
        // 可能只是系统限制（如 Android 10+ 的 ptrace 限制）
        return false;
    }

    // 有 TracerPid，进一步验证
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        LOGW("ptrace(PTRACE_TRACEME) failed and TracerPid exists - being traced");
        return true;
    }
    // 成功 attach 后立即 detach
    ptrace(PTRACE_DETACH, 0, 0, 0);
    return false;
}

/**
 * 检测 Frida 特征：检查特定端口（更全面）
 */
bool checkFridaPort() {
    std::ifstream tcp4File("/proc/net/tcp");
    std::ifstream tcp6File("/proc/net/tcp6");

    if (!tcp4File.is_open() && !tcp6File.is_open()) {
        return false;
    }

    // Frida 默认端口的十六进制表示
    // 27042 = 0x6992, 27043 = 0x6993, 27045 = 0x6995
    const char* fridaPorts[] = {"697A", "697B", "697C", "697D", "6992", "6993", "6995"};

    std::string line;

    // 检查 IPv4
    while (std::getline(tcp4File, line)) {
        for (const char* port : fridaPorts) {
            if (line.find(port) != std::string::npos) {
                LOGW("Frida port detected in tcp: %s", port);
                return true;
            }
        }
    }

    // 检查 IPv6
    while (std::getline(tcp6File, line)) {
        for (const char* port : fridaPorts) {
            if (line.find(port) != std::string::npos) {
                LOGW("Frida port detected in tcp6: %s", port);
                return true;
            }
        }
    }

    return false;
}

/**
 * 检测 Frida 线程特征
 * Frida 会创建特定名称的线程
 */
bool checkFridaThreads() {
    DIR* taskDir = opendir("/proc/self/task");
    if (taskDir == nullptr) {
        return false;
    }

    struct dirent* entry;
    while ((entry = readdir(taskDir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        char commPath[256];
        snprintf(commPath, sizeof(commPath), "/proc/self/task/%s/comm", entry->d_name);

        std::ifstream commFile(commPath);
        if (commFile.is_open()) {
            std::string threadName;
            std::getline(commFile, threadName);

            // Frida 的典型线程名
            if (threadName.find("gmain") != std::string::npos ||
                threadName.find("gum-js-loop") != std::string::npos ||
                threadName.find("gdbus") != std::string::npos ||
                threadName.find("pool-frida") != std::string::npos) {
                LOGW("Frida thread detected: %s", threadName.c_str());
                closedir(taskDir);
                return true;
            }
        }
    }
    closedir(taskDir);
    return false;
}

/**
 * 检测 Frida 特征文件
 */
bool checkFridaFiles() {
    const char* fridaFiles[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida",
        "/data/local/tmp/re.frida.server"
    };

    for (const char* file : fridaFiles) {
        struct stat fileStat{};
        if (stat(file, &fileStat) == 0) {
            LOGW("Frida file detected: %s", file);
            return true;
        }
    }
    return false;
}

/**
 * 检测内存中的 Frida 特征字符串
 * 通过扫描内存映射查找 Frida 的典型符号
 */
bool checkFridaInMemory() {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        // 检查是否包含 Frida 相关的库或路径
        if (line.find("frida") != std::string::npos ||
            line.find("linjector") != std::string::npos) {
            LOGW("Frida signature in memory maps: %s", line.c_str());
            return true;
        }
    }
    return false;
}

/**
 * 内联 Hook 检测
 * 检查关键函数的前几个字节是否被修改
 */
bool checkInlineHook() {
    // 获取 libc 中 open 函数的地址
    void* openAddr = dlsym(RTLD_DEFAULT, "open");
    if (openAddr == nullptr) {
        return false;
    }

    // 读取函数的前 4 个字节
    unsigned char* bytes = static_cast<unsigned char*>(openAddr);

    // ARM64 的典型跳转指令：
    // B 指令：0x14000000 (无条件跳转)
    // LDR + BR：用于长跳转
    unsigned int instr = *reinterpret_cast<unsigned int*>(bytes);

    // 检查是否为跳转指令（可能是 hook）
    // ARM64 B 指令：opcode = 0x14 (最高字节)
    if ((instr & 0xFC000000) == 0x14000000) {
        LOGW("Possible inline hook detected at open()");
        return true;
    }

    // 检查 LDR 指令 (可能是 Frida 的 trampoline)
    if ((instr & 0xFF000000) == 0x58000000) {
        LOGW("Possible trampoline detected at open()");
        return true;
    }

    return false;
}

/**
 * 检测 Root：检查 su 文件
 * 不仅检查存在，还检查可执行性
 */
bool checkSuBinary() {
    const char* suPaths[] = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/vendor/bin/su"
    };

    for (const char* path : suPaths) {
        struct stat fileStat{};
        if (stat(path, &fileStat) == 0) {
            // 检查是否为可执行文件
            if (fileStat.st_mode & S_IXUSR) {
                LOGW("Su binary found and executable: %s", path);
                return true;
            }
        }
    }
    return false;
}

/**
 * 检测 Root：检查系统属性
 */
bool checkRootProperties() {
    char value[PROP_VALUE_MAX];

    // ro.debuggable 应该为 0
    __system_property_get("ro.debuggable", value);
    if (strcmp(value, "1") == 0) {
        LOGW("ro.debuggable = 1");
        return true;
    }

    // ro.secure 应该为 1
    __system_property_get("ro.secure", value);
    if (strcmp(value, "0") == 0) {
        LOGW("ro.secure = 0");
        return true;
    }

    // 检测 test-keys
    __system_property_get("ro.build.tags", value);
    if (strstr(value, "test-keys") != nullptr) {
        LOGW("Build tags contain test-keys: %s", value);
        return true;
    }

    return false;
}

/**
 * 检测 Root：检查危险目录的写权限
 */
bool checkDangerousPermissions() {
    const char* paths[] = {
            "/system",
            "/system/bin",
            "/system/xbin"
    };

    for (const char* path : paths) {
        if (access(path, W_OK) == 0) {
            LOGW("Write access to system directory: %s", path);
            return true;
        }
    }
    return false;
}

/**
 * 检测 Hook：扫描已加载的库
 */
bool checkLoadedLibraries() {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) {
        return false;
    }

    const char* suspiciousLibs[] = {
            "frida",
            "xposed",
            "substrate",
            "libriru",
            "lsposed"
    };

    std::string line;
    while (std::getline(mapsFile, line)) {
        for (const char* lib : suspiciousLibs) {
            if (line.find(lib) != std::string::npos) {
                LOGW("Suspicious library in memory: %s", lib);
                LOGW("Maps line: %s", line.c_str());
                return true;
            }
        }
    }
    return false;
}

/**
 * 综合 Frida 检测
 */
bool detectFrida() {
    bool detected = false;

    if (checkFridaPort()) detected = true;
    if (checkFridaThreads()) detected = true;
    if (checkFridaFiles()) detected = true;
    if (checkFridaInMemory()) detected = true;
    if (checkInlineHook()) detected = true;

    return detected;
}

/**
 * 检测模拟器：CPU 特征
 */
bool checkEmulatorCpu() {
    std::ifstream cpuinfoFile("/proc/cpuinfo");
    if (!cpuinfoFile.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(cpuinfoFile)),
                        std::istreambuf_iterator<char>());

    // 检测 x86 架构（大多数真实设备是 ARM）
    if (content.find("Intel") != std::string::npos ||
        content.find("AMD") != std::string::npos ||
        content.find("GenuineIntel") != std::string::npos) {
        LOGW("x86 CPU detected");
        return true;
    }

    // 检测模拟器特征
    if (content.find("goldfish") != std::string::npos ||
        content.find("ranchu") != std::string::npos ||
        content.find("vbox") != std::string::npos) {
        LOGW("Emulator CPU signature detected");
        return true;
    }

    return false;
}

/**
 * 检测模拟器：QEMU 特征文件
 */
bool checkQemuFiles() {
    const char* qemuFiles[] = {
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
    };

    for (const char* file : qemuFiles) {
        struct stat fileStat{};
        if (stat(file, &fileStat) == 0) {
            LOGW("QEMU file detected: %s", file);
            return true;
        }
    }
    return false;
}

/**
 * 检测内存中的可疑字符串
 */
bool checkSuspiciousStrings() {
    std::ifstream cmdlineFile("/proc/self/cmdline");
    if (!cmdlineFile.is_open()) {
        return false;
    }

    std::string cmdline;
    std::getline(cmdlineFile, cmdline, '\0');

    const char* suspiciousStrs[] = {
            "frida",
            "gdb",
            "gdbserver",
            "lldb",
            "ida",
            "substrate"
    };

    for (const char* str : suspiciousStrs) {
        if (cmdline.find(str) != std::string::npos) {
            LOGW("Suspicious string in process: %s", str);
            return true;
        }
    }
    return false;
}

/**
 * 检测 LD_PRELOAD
 */
bool checkLdPreload() {
    char* ldPreload = getenv("LD_PRELOAD");
    if (ldPreload != nullptr && strlen(ldPreload) > 0) {
        LOGW("LD_PRELOAD detected: %s", ldPreload);
        return true;
    }
    return false;
}

/**
 * 检测异常的文件描述符
 * 调整阈值以减少误报
 */
bool checkAbnormalFd() {
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr) {
        return false;
    }

    int fdCount = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] != '.') {
            fdCount++;
        }
    }
    closedir(dir);

    // 提高阈值到 200，减少误报
    // 现代应用可能使用很多 fd（网络、文件、线程等）
    if (fdCount > 200) {
        LOGW("Abnormal FD count: %d", fdCount);
        return true;
    }

    return false;
}

// ============ JNI 导出函数 ============

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_grtsinry43_environmentdetector_security_NativeSecurityDetector_nativeCheckRoot(
        JNIEnv* env,
        jclass clazz) {

    LOGD("Native Root check started");

    // 验证调用完整性 - 防止直接调用 .so
    if (!verifyNativeCall(env)) {
        LOGE("Call verification failed - possible SO hijacking");
        return true; // 检测到异常，返回 true
    }

    bool isRooted = false;

    // 综合多个检测点
    if (checkSuBinary()) isRooted = true;
    if (checkRootProperties()) isRooted = true;
    if (checkDangerousPermissions()) isRooted = true;

    LOGD("Native Root check result: %s", isRooted ? "ROOTED" : "CLEAN");
    return isRooted;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_grtsinry43_environmentdetector_security_NativeSecurityDetector_nativeCheckHook(
        JNIEnv* env,
        jclass clazz) {

    LOGD("Native Hook check started");

    bool isHooked = false;

    if (checkLoadedLibraries()) isHooked = true;
    if (detectFrida()) isHooked = true;
    if (checkSuspiciousStrings()) isHooked = true;
    if (checkLdPreload()) isHooked = true;

    LOGD("Native Hook check result: %s", isHooked ? "HOOKED" : "CLEAN");
    return isHooked;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_grtsinry43_environmentdetector_security_NativeSecurityDetector_nativeCheckDebugger(
        JNIEnv* env,
        jclass clazz) {

    LOGD("Native Debugger check started");

    bool isDebugging = false;

    // 只检查 TracerPid，移除 ptrace 检测以减少误报
    if (checkTracerPid()) isDebugging = true;

    // checkAbnormalFd 也可能误报，只作为辅助判断
    // if (checkAbnormalFd()) isDebugging = true;

    LOGD("Native Debugger check result: %s", isDebugging ? "DEBUGGING" : "CLEAN");
    return isDebugging;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_grtsinry43_environmentdetector_security_NativeSecurityDetector_nativeCheckEmulator(
        JNIEnv* env,
        jclass clazz) {

    LOGD("Native Emulator check started");

    bool isEmulator = false;

    if (checkEmulatorCpu()) isEmulator = true;
    if (checkQemuFiles()) isEmulator = true;

    LOGD("Native Emulator check result: %s", isEmulator ? "EMULATOR" : "DEVICE");
    return isEmulator;
}
