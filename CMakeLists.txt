cmake_minimum_required(VERSION 3.5)

project(GTKCrypto)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(GTKCRYPTO_VERSION_MAJOR "1")
set(GTKCRYPTO_VERSION_MINOR "0")
set(GTKCRYPTO_VERSION_PATCH "2")
set(GTKCRYPTO_VERSION "${GTKCRYPTO_VERSION_MAJOR}.${GTKCRYPTO_VERSION_MINOR}.${GTKCRYPTO_VERSION_PATCH}")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra -O2 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-align")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")
# libgpgme need Largefile support
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64")
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pie -fPIE")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-add-needed -Wl,--as-needed -Wl,--no-undefined")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,--no-add-needed -Wl,--as-needed")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
endif()

find_package(PkgConfig REQUIRED)
find_package(Gcrypt 1.7.0 REQUIRED)
find_package(Gpgme 1.8.0 REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0 >= 3.20.0)

include_directories(${GTK3_INCLUDE_DIRS}
        ${GCRYPT_INCLUDE_DIR}
        ${GPGME_INCLUDE_DIR})

link_directories(${GTK3_LIBRARY_DIRS}
        ${GCRYPT_LIBRARY_DIR}
        ${GPGME_LIBRARY_DIR})

add_definitions(${GTK3_CFLAGS_OTHER}
        ${GCRYPT_CFLAGS_OTHER}
        ${GPGME_CFLAGS_OTHER})

set(HEADER_FILES
        src/common-callbacks.h
        src/common-widgets.h
        src/crypt-common.h
        src/decrypt-files-cb.h
        src/encrypt-files-cb.h
        src/gpgme-misc.h
        src/gtkcrypto.h
        src/hash.h
        src/main.h
        src/misc-style.h src/cleanup.h)

set(SOURCE_FILES
        src/main.c
        src/message-dialog.c
        src/compare-file-hash-cb.c
        src/compute-hash-cb.c
        src/choose-file.c
        src/common-callbacks.c
        src/hash.c
        src/misc-style.c
        src/get-file-size.c
        src/spinner.c
        src/common-widgets.c
        src/encrypt-file.c
        src/mcw-sensitivity.c
        src/hmac.c
        src/decrypt-file.c
        src/crypt-common.c
        src/decrypt-files-cb.c
        src/gpgme-misc.c
        src/sign-file-cb.c
        src/verify-signature-cb.c
        src/encrypt-files-cb.c
        src/app.c
        src/cleanup.c
        src/text-cb.c
        src/get-builder.c)

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(${PROJECT_NAME}
        ${GTK3_LIBRARIES}
        ${GCRYPT_LIBRARIES}
        ${GPGME_LIBRARIES})

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "gtkcrypto")

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES data/com.github.paolostivanin.GTKCrypto.desktop DESTINATION share/applications)
install(FILES data/com.github.paolostivanin.GTKCrypto.appdata.xml DESTINATION share/metainfo)

install(FILES src/ui/gtkcrypto.ui DESTINATION share/gtkcrypto)
install(FILES data/icons/icon_x16.png DESTINATION share/icons/hicolor/16x16/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x24.png DESTINATION share/icons/hicolor/24x24/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x32.png DESTINATION share/icons/hicolor/32x32/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x48.png DESTINATION share/icons/hicolor/48x48/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x64.png DESTINATION share/icons/hicolor/64x64/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x128.png DESTINATION share/icons/hicolor/128x128/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x256.png DESTINATION share/icons/hicolor/256x256/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/icon_x512.png DESTINATION share/icons/hicolor/512x512/apps RENAME com.github.paolostivanin.GTKCrypto.png)
install(FILES data/icons/gtkcrypto.svg DESTINATION share/icons/hicolor/scalable/apps RENAME com.github.paolostivanin.GTKCrypto.svg)
