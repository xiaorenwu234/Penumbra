cmake_minimum_required(VERSION 3.16)
project(ghostbpf-observ LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---- third-party paths ---------------------------------------------------
set(THIRD_PARTY ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
set(VMLINUX_H   ${THIRD_PARTY}/vmlinux.h/include/x86/vmlinux.h)

# ---- vendored libbpf (static, from source) -------------------------------
include(ExternalProject)
ExternalProject_Add(libbpf_ext
  PREFIX            libbpf
  SOURCE_DIR        ${THIRD_PARTY}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     make -C ${THIRD_PARTY}/libbpf/src
                    CC=${CMAKE_C_COMPILER}
                    CFLAGS=-fPIC
                    BUILD_STATIC_ONLY=1
                    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/obj
                    LIBDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
                    INCLUDEDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/include
                    UAPIDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/include
                    install install_uapi_headers
  BUILD_IN_SOURCE   1
  INSTALL_COMMAND   ""
  BUILD_BYPRODUCTS  ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a
)
set(LIBBPF_A   ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
set(LIBBPF_INC ${CMAKE_CURRENT_BINARY_DIR}/libbpf/include)

# ---- bpftool (for skeleton generation) -----------------------------------
set(BPFTOOL_DIR ${THIRD_PARTY}/bpftool/src)
set(BPFTOOL_BIN ${BPFTOOL_DIR}/bootstrap/bpftool)

ExternalProject_Add(bpftool_ext
  PREFIX            bpftool
  SOURCE_DIR        ${BPFTOOL_DIR}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     make -C ${BPFTOOL_DIR}
                    CC=${CMAKE_C_COMPILER}
                    bootstrap
  BUILD_IN_SOURCE   1
  INSTALL_COMMAND   ""
  BUILD_BYPRODUCTS  ${BPFTOOL_BIN}
)

# ---- BPF programs -------------------------------------------------------
set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bpf/observ.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/observ.bpf.o)

# Shared BPF headers; edits must retrigger both skeleton builds.
set(BPF_HDRS
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/cri.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/observ_common.h
)

add_custom_command(
    OUTPUT  ${BPF_OBJ}
    COMMAND clang -O2 -g -target bpf
            -I ${CMAKE_CURRENT_SOURCE_DIR}/bpf
            -I ${THIRD_PARTY}/vmlinux.h/include/x86
            -I ${LIBBPF_INC}
            -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${BPF_HDRS} ${VMLINUX_H}
    COMMENT "Compiling BPF: observ.bpf.o"
)

set(ENFORCE_BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bpf/enforce.bpf.c)
set(ENFORCE_BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/enforce.bpf.o)

add_custom_command(
    OUTPUT  ${ENFORCE_BPF_OBJ}
    COMMAND clang -O2 -g -target bpf
            -I ${CMAKE_CURRENT_SOURCE_DIR}/bpf
            -I ${THIRD_PARTY}/vmlinux.h/include/x86
            -I ${LIBBPF_INC}
            -c ${ENFORCE_BPF_SRC} -o ${ENFORCE_BPF_OBJ}
    DEPENDS ${ENFORCE_BPF_SRC} ${BPF_HDRS} ${VMLINUX_H}
    COMMENT "Compiling BPF: enforce.bpf.o"
)
add_custom_target(bpf_progs ALL DEPENDS ${BPF_OBJ} ${ENFORCE_BPF_OBJ})

# ---- skeleton generation -------------------------------------------------
set(SKEL_H ${CMAKE_CURRENT_BINARY_DIR}/observ.skel.h)
add_custom_command(
    OUTPUT  ${SKEL_H}
    COMMAND ${BPFTOOL_BIN} gen skeleton ${BPF_OBJ} > ${SKEL_H}
    DEPENDS ${BPF_OBJ} bpftool_ext
    COMMENT "Generating skeleton: observ.skel.h"
)

set(ENFORCE_SKEL_H ${CMAKE_CURRENT_BINARY_DIR}/enforce.skel.h)
add_custom_command(
    OUTPUT  ${ENFORCE_SKEL_H}
    COMMAND ${BPFTOOL_BIN} gen skeleton ${ENFORCE_BPF_OBJ} > ${ENFORCE_SKEL_H}
    DEPENDS ${ENFORCE_BPF_OBJ} bpftool_ext
    COMMENT "Generating skeleton: enforce.skel.h"
)
add_custom_target(skeleton ALL DEPENDS ${SKEL_H} ${ENFORCE_SKEL_H})

# ---- static library: libghostbpf-observ.a --------------------------------
add_library(ghostbpf-observ STATIC
    src/observer.cpp
    src/audit_engine.cpp
    src/enforcer.cpp
    src/socket_server.cpp
)
target_include_directories(ghostbpf-observ PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INC}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
)
target_link_libraries(ghostbpf-observ PUBLIC ${LIBBPF_A} elf z pthread)
add_dependencies(ghostbpf-observ libbpf_ext skeleton)

# ---- demo executable -----------------------------------------------------
add_executable(observ_demo src/demo.cpp)
target_include_directories(observ_demo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INC}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
)
target_link_libraries(observ_demo PRIVATE ghostbpf-observ)
add_dependencies(observ_demo ghostbpf-observ)

# ---- daemon executable ---------------------------------------------------
add_executable(observ_daemon src/daemon.cpp)
target_include_directories(observ_daemon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INC}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
)
target_link_libraries(observ_daemon PRIVATE ghostbpf-observ)
add_dependencies(observ_daemon ghostbpf-observ)
