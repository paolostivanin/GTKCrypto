find_path(GPGME_INCLUDE_DIR gpgme.h)

find_library(GPGME_LIBRARIES gpgme)

mark_as_advanced(GPGME_LIBRARIES GPGME_INCLUDE_DIR)

if(GPGME_INCLUDE_DIR AND EXISTS "${GPGME_INCLUDE_DIR}/gpgme.h")
    file(STRINGS "${GPGME_INCLUDE_DIR}/gcrypt.h" GPGME_H REGEX "^#define GPGME_VERSION \"[^\"]*\"$")
    string(REGEX REPLACE "^.*GPGME_VERSION \"([0-9]+).*$" "\\1" GPGME_VERSION_MAJOR "${GPGME_H}")
    string(REGEX REPLACE "^.*GPGME_VERSION \"[0-9]+\\.([0-9]+).*$" "\\1" GPGME_VERSION_MINOR  "${GPGME_H}")
    string(REGEX REPLACE "^.*GPGME_VERSION \"[0-9]+\\.[0-9]+\\.([0-9]+).*$" "\\1" GPGME_VERSION_PATCH "${GPGME_H}")
    set(GPGME_VERSION_STRING "${GPGME_VERSION_MAJOR}.${GPGME_VERSION_MINOR}.${GPGME_VERSION_PATCH}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Gpgme DEFAULT_MSG GPGME_LIBRARIES GPGME_INCLUDE_DIR)
