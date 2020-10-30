#CMake工具最低版本要求,使用命令“cmake --version”查看
cmake_minimum_required(VERSION 2.8)

#项目名称
project(AES_encryption)

MESSAGE(STATUS "Project: AES_encryption")

#设置交叉编译器
option(ARM_CROSS_COMPILE "Arm cross compiling option" ON)
if(ARM_CROSS_COMPILE)
    MESSAGE(STATUS "Arm cross compiling...")
    # 设置目标系统
    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR arm)

    # 设置工具链目录
    set(TOOL_CHAIN_DIR /opt/hisi-linux/x86-arm/aarch64-himix100-linux)
    set(TOOL_CHAIN_INCLUDE 
        ${TOOL_CHAIN_DIR}/include
        )
    set(TOOL_CHAIN_LIB 
        ${TOOL_CHAIN_DIR}/lib
        )

    # 设置编译器
    set(CMAKE_C_COMPILER "aarch64-himix100-linux-gcc")
    set(CMAKE_CXX_COMPILER "aarch64-himix100-linux-g++")

    MESSAGE(STATUS "CMAKE_C_COMPILER:" ${CMAKE_C_COMPILER})
    MESSAGE(STATUS "CMAKE_CXX_COMPILER:" ${CMAKE_CXX_COMPILER})
    # 设置Cmake查找主路径
    set(CMAKE_FIND_ROOT_PATH ${TOOL_CHAIN_DIR})

    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    # 只在指定目录下查找库文件
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    # 只在指定目录下查找头文件
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    # 只在指定目录下查找依赖包
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

    include_directories(
        ${TOOL_CHAIN_DIR}/include
        )

    set(CMAKE_INCLUDE_PATH 
        ${TOOL_CHAIN_INCLUDE}
        )

    set(CMAKE_LIBRARY_PATH 
        ${TOOL_CHAIN_LIB}
        )
endif(ARM_CROSS_COMPILE)

#添加头文件的路径 
include_directories( 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/cryptopp
)

#添加动态连接库的路径
link_directories(
    ${CMAKE_SOURCE_DIR}/lib/3559
)

#增加源文件的编译选项  add_compile_options

#给g++添加编译选项
set(CMAKE_CXX_FLAGS "-Wall -fpermissive -std=c++11")

#添加链接库选项
#set(CMAKE_EXE_LINKER_FLAGS "")

#为源文件的编译添加由-D定义的标志  add_definitions

#添加源文件路径
aux_source_directory(${CMAKE_SOURCE_DIR}/src/. SRC)

#add_executable(想要生成的程序名 源文件)
add_executable(${PROJECT_NAME} ${SRC})

#添加编译时的依赖库
target_link_libraries(${PROJECT_NAME} -lcryptopp -lpthread -lstdc++)