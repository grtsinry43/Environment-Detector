#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "AntiHook"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// 存储原始的 JNIEnv，用于验证调用来源
static JavaVM* g_jvm = nullptr;
static jobject g_context = nullptr;

/**
 * 验证调用者是否来自我们的应用
 * 防止其他应用通过 dlopen 加载我们的 .so 并直接调用
 */
bool verifyCallerIntegrity(JNIEnv* env) {
    if (env == nullptr || g_jvm == nullptr) {
        LOGW("Invalid environment - possible direct .so call");
        return false;
    }

    // 检查 JNIEnv 是否属于我们的 JavaVM
    JavaVM* vm = nullptr;
    if (env->GetJavaVM(&vm) != JNI_OK || vm != g_jvm) {
        LOGW("JavaVM mismatch - possible hijacked call");
        return false;
    }

    // 检查调用栈，确保来自我们的应用
    jclass threadClass = env->FindClass("java/lang/Thread");
    if (threadClass == nullptr) return false;

    jmethodID currentThread = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
    jmethodID getStackTrace = env->GetMethodID(threadClass, "getStackTrace", "()[Ljava/lang/StackTraceElement;");

    if (currentThread == nullptr || getStackTrace == nullptr) {
        env->DeleteLocalRef(threadClass);
        return false;
    }

    jobject thread = env->CallStaticObjectMethod(threadClass, currentThread);
    jobjectArray stackTrace = (jobjectArray)env->CallObjectMethod(thread, getStackTrace);

    if (stackTrace != nullptr) {
        jsize stackSize = env->GetArrayLength(stackTrace);

        // 检查调用栈中是否包含我们的包名
        jclass stackTraceElementClass = env->FindClass("java/lang/StackTraceElement");
        jmethodID getClassName = env->GetMethodID(stackTraceElementClass, "getClassName", "()Ljava/lang/String;");

        bool foundOurPackage = false;
        for (jsize i = 0; i < stackSize && i < 20; i++) {
            jobject element = env->GetObjectArrayElement(stackTrace, i);
            jstring className = (jstring)env->CallObjectMethod(element, getClassName);

            const char* classNameStr = env->GetStringUTFChars(className, nullptr);
            if (strstr(classNameStr, "com.grtsinry43.environmentdetector") != nullptr) {
                foundOurPackage = true;
            }
            env->ReleaseStringUTFChars(className, classNameStr);
            env->DeleteLocalRef(element);
            env->DeleteLocalRef(className);

            if (foundOurPackage) break;
        }

        env->DeleteLocalRef(stackTraceElementClass);
        env->DeleteLocalRef(stackTrace);
        env->DeleteLocalRef(thread);
        env->DeleteLocalRef(threadClass);

        if (!foundOurPackage) {
            LOGW("Call stack doesn't contain our package - possible external caller");
            return false;
        }
    }

    return true;
}

/**
 * 检测当前进程是否就是我们的应用进程
 * 防止攻击者在另一个进程中 dlopen 我们的 .so
 */
bool verifyProcessIntegrity() {
    // 读取 /proc/self/cmdline 获取进程名
    FILE* fp = fopen("/proc/self/cmdline", "r");
    if (fp == nullptr) {
        return false;
    }

    char processName[256] = {0};
    fgets(processName, sizeof(processName), fp);
    fclose(fp);

    // 检查进程名是否匹配
    if (strstr(processName, "com.grtsinry43.environmentdetector") == nullptr) {
        LOGW("Process name mismatch: %s", processName);
        return false;
    }

    return true;
}

/**
 * 检测 .so 是否被非法加载
 * 通过检查加载路径是否在我们的应用目录下
 */
bool verifySoLoadPath() {
    Dl_info info;
    // 获取当前函数所在的 .so 信息
    if (dladdr((void*)verifySoLoadPath, &info) == 0) {
        return false;
    }

    const char* soPath = info.dli_fname;
    if (soPath == nullptr) {
        return false;
    }

    // 检查 .so 路径是否在 /data/app/com.grtsinry43.environmentdetector-xxx/ 下
    if (strstr(soPath, "/data/app/") == nullptr ||
        strstr(soPath, "com.grtsinry43.environmentdetector") == nullptr) {
        LOGW("SO loaded from suspicious path: %s", soPath);
        return false;
    }

    return true;
}

/**
 * 检测函数是否被 inline hook
 * 通过计算函数的校验和
 */
bool detectFunctionHook(void* funcPtr, const unsigned char* expectedBytes, size_t len) {
    if (funcPtr == nullptr || expectedBytes == nullptr || len == 0) {
        return false;
    }

    unsigned char* actualBytes = static_cast<unsigned char*>(funcPtr);

    // 比较前 N 个字节
    for (size_t i = 0; i < len; i++) {
        if (actualBytes[i] != expectedBytes[i]) {
            LOGW("Function hook detected at offset %zu: expected 0x%02x, got 0x%02x",
                 i, expectedBytes[i], actualBytes[i]);
            return true;
        }
    }

    return false;
}

/**
 * 初始化反 Hook 保护
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_grtsinry43_environmentdetector_security_NativeSecurityDetector_initAntiHook(
        JNIEnv* env,
        jclass clazz,
        jobject context) {

    // 保存 JavaVM 和 Context
    env->GetJavaVM(&g_jvm);
    g_context = env->NewGlobalRef(context);

    LOGW("Anti-hook protection initialized");
}

/**
 * 验证调用完整性（供其他 native 函数调用）
 */
bool verifyNativeCall(JNIEnv* env) {
    if (!verifyProcessIntegrity()) {
        LOGW("Process integrity check failed");
        return false;
    }

    if (!verifySoLoadPath()) {
        LOGW("SO load path check failed");
        return false;
    }

    if (!verifyCallerIntegrity(env)) {
        LOGW("Caller integrity check failed");
        return false;
    }

    return true;
}