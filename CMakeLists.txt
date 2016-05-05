cmake_minimum_required(VERSION 3.3)

project(GTKCrypto)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -Wformat=2 -fstack-protector-all -fPIE -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")

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
    src/gtkcrypto.h
    src/hmac.c
    src/main.c
    src/main.h
    src/message_dialog.c
    src/random_write.c
    src/hash/md5.c
    src/hash/gost94.c
    src/hash/sha1.c
    src/hash/sha2.c
    src/hash/sha3.c
    src/hash/whirlpool.c
    src/text.c
    src/text.h
    src/zero_write.c)

add_executable(GTKCrypto ${SOURCE_FILES})
target_link_libraries(GTKCrypto ${GTK3_LIBRARIES} -lgcrypt)
