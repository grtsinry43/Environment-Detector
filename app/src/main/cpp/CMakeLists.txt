cmake_minimum_required(VERSION 3.22.1)

project("security_native")

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加安全编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2 -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2")

# 添加混淆选项（发布版本）
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fvisibility=hidden -ffunction-sections -fdata-sections")

# 创建共享库
add_library(
        security_native
        SHARED
        security_native.cpp
        anti_hook.cpp
)

# 链接日志库
target_link_libraries(
        security_native
        log
        dl
)
