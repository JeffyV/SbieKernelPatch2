cmake_minimum_required(VERSION 4.2.2)

# c++ modules support
set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "d0edc3af-4c50-42ea-a356-e2862fe7a444")
# import std module support
set(CMAKE_CXX_MODULE_STD ON)

project(SbieKernelPatch2 CXX)

set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Detail output" FORCE)
set(CMAKE_CXX_STANDARD 26)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion)

add_library(${PROJECT_NAME}_Modules)
target_sources(${PROJECT_NAME}_Modules PUBLIC
        FILE_SET CXX_MODULES
        BASE_DIRS ${CMAKE_SOURCE_DIR}
        FILES
        Utils/DriverManager.cppm
        Utils/DriverController.cppm
        Utils/HostUtils.cppm
        Utils/Logger.cppm
        Utils/PdbUtils.cppm
        Utils/CertGenerator.cppm
        Utils/FileUtils.cppm
)


add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_Modules)
target_link_libraries(${PROJECT_NAME} PRIVATE ntdll dbghelp bcrypt crypt32)