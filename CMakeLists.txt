cmake_minimum_required(VERSION 3.3)
project(4_PolCrypt)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

include_directories(${GTK3_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS})

add_definitions(${GTK3_CFLAGS_OTHER})

set(SOURCE_FILES
    src/check_b64.c
    src/check_pkcs7.c
    src/check_pwd.c
    src/create_logo.c
    src/create_popover.c
    src/crypt_file.c
    src/crypt_file.h
    src/delete_input_file.c
    src/get_file_size.c
    src/gost94.c
    src/gtkcrypto.h
    src/hmac.c
    src/main.c
    src/main.h
    src/md5.c
    src/message_dialog.c
    src/random_write.c
    src/sha1.c
    src/sha2.c
    src/sha3.c
    src/text.c
    src/text.h
    src/whirlpool.c
    src/zero_write.c)

add_executable(PolCrypt ${SOURCE_FILES})
target_link_libraries(PolCrypt ${GTK3_LIBRARIES})
