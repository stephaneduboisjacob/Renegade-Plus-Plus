cmake_minimum_required(VERSION 3.20)
project(renegade_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
find_package(SQLite3 REQUIRED)
pkg_check_modules(LIBSSH REQUIRED IMPORTED_TARGET libssh)
pkg_check_modules(ARGON2 REQUIRED IMPORTED_TARGET libargon2)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)

# Keep libarchive's optional development include path local to its one C API
# translation unit. This avoids shadowing the platform iconv.h for other files.
set_source_files_properties(src/archive_store.cpp PROPERTIES
    INCLUDE_DIRECTORIES "${LIBARCHIVE_INCLUDE_DIRS}")
find_library(LIBARCHIVE_RUNTIME_LIBRARY NAMES archive)
if(NOT LIBARCHIVE_RUNTIME_LIBRARY)
    find_file(LIBARCHIVE_RUNTIME_LIBRARY
        NAMES libarchive.so.14 libarchive.so.13 libarchive.so.12 libarchive.so.11
        PATHS
            "/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
            "/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
            "/usr/lib"
            "/lib"
        NO_DEFAULT_PATH)
endif()
set(LIBARCHIVE_EXTRA_LIBRARY_DIRS "")
if(NOT LIBARCHIVE_RUNTIME_LIBRARY)
    set(LIBARCHIVE_RUNTIME_LIBRARY ${LIBARCHIVE_LINK_LIBRARIES})
    set(LIBARCHIVE_EXTRA_LIBRARY_DIRS ${LIBARCHIVE_LIBRARY_DIRS})
endif()

add_executable(renegade-cpp
    src/account_store.cpp
    src/archive_store.cpp
    src/community_store.cpp
    src/file_store.cpp
    src/legacy_acs.cpp
    src/legacy_mci.cpp
    src/main.cpp
    src/message_store.cpp
    src/secure_sftp.cpp
    src/server.cpp
    src/terminal.cpp
)

if(LIBARCHIVE_EXTRA_LIBRARY_DIRS)
    target_link_directories(renegade-cpp PRIVATE ${LIBARCHIVE_EXTRA_LIBRARY_DIRS})
endif()

target_link_libraries(renegade-cpp PRIVATE
    PkgConfig::LIBSSH
    PkgConfig::ARGON2
    ${LIBARCHIVE_RUNTIME_LIBRARY}
    SQLite::SQLite3
)

target_compile_options(renegade-cpp PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)
