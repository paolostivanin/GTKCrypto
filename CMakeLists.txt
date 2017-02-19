cmake_minimum_required(VERSION 3.5)

project(GTKCrypto)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=c11 -O3 -Wformat=2 -fstack-protector-all -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pie -fpie -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpointer-arith -Wbad-function-cast -Wcast-align -Wno-missing-field-initializers")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-return-type -Wno-cast-qual -Wno-sign-compare -Wl,--sort-common,--as-needed,-z,relro")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

include_directories(${GTK3_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS})

add_definitions(${GTK3_CFLAGS_OTHER})

set(SOURCE_FILES
        src/main.c
        src/create-logo.c
        src/message-dialog.c
        src/app-startup.c
        src/app-activate.c
        src/create-mainwin.c
        src/add-boxes-grid.c
        src/app-quit.c
        src/app-about.c
        src/compare-file-hash-cb.c
        src/compute-hash-cb.c
        src/choose-file.c
        src/common-callbacks.c
        src/hash.c
        src/mfree.c
        src/css.c
        src/get-file-size.c
        src/spinner.c
        src/encrypt-file-cb.c
        src/common-widgets.c
        src/encrypt-file.c
        src/mcw-sensitivity.c
        src/hmac.c
        src/decrypt-file.c
        src/crypt-common.c
        src/decrypt-file-cb.c
        src/gpgme-misc.c
        src/sign-file-cb.c
        src/verify-signature-cb.c
        src/check-file-extension.c)

add_executable(GTKCrypto ${SOURCE_FILES})
target_link_libraries(GTKCrypto ${GTK3_LIBRARIES} -lgcrypt -lgpgme)
