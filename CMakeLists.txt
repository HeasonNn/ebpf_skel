cmake_minimum_required(VERSION 3.10)
project(mmap_monitor C)

# 设置 C 标准
set(CMAKE_C_STANDARD 11)

# 查找 libbpf 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
if(NOT LIBBPF_FOUND)
    message(FATAL_ERROR "libbpf 未找到, 请确保已安装并在 pkg-config 路径中")
endif()

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(BPF_SRC ${SRC_DIR}/mmap_monitor.bpf.c)
set(USER_SRC ${SRC_DIR}/mmap_monitor.c)

set(VMLINUX_DIR ${CMAKE_SOURCE_DIR}/vmlinux)
set(VMLINUX_H ${VMLINUX_DIR}/vmlinux.h)

# 定义 BPF 对象文件的输出路径
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/mmap_monitor.bpf.o)

# 编译 eBPF 程序为对象文件
add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND clang
            -target bpf
            -g
            -O2
            -c
            -I${VMLINUX_DIR}
            -I${SRC_DIR}
            ${BPF_SRC}
            -o ${BPF_OBJECT}
    DEPENDS ${BPF_SRC} ${VMLINUX_H}
    COMMENT "Compiling eBPF program: mmap_monitor.bpf.c"
)

# 创建 eBPF 目标
add_custom_target(ebpf_target DEPENDS ${BPF_OBJECT})

# 编译主程序 mmap_monitor.c
add_executable(mmap_monitor ${USER_SRC})

# 确保在编译可执行文件之前编译 eBPF 程序
add_dependencies(mmap_monitor ebpf_target)

# 设置包含目录，仅对 mmap_monitor 目标
target_include_directories(mmap_monitor PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

# 添加编译选项（来自 pkg-config）
target_compile_options(mmap_monitor PRIVATE ${LIBBPF_CFLAGS})

# 链接 libbpf 库和其他必要的库
target_link_libraries(mmap_monitor PRIVATE ${LIBBPF_LIBRARIES})

# 添加链接选项（来自 pkg-config）
target_link_options(mmap_monitor PRIVATE ${LIBBPF_LDFLAGS})

# 设置 RPATH，以便在运行时找到 libbpf 库
set_target_properties(mmap_monitor PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS}"
)

# 安装目标和 eBPF 对象文件
install(TARGETS mmap_monitor RUNTIME DESTINATION bin)
install(FILES ${BPF_OBJECT} DESTINATION bin)
