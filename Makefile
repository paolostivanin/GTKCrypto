CFLAGS = -Wall -Wextra -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat=2 -fstack-protector-all -fPIE -Wno-unused-result -Wno-return-type -Wno-missing-field-initializers
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt -lnettle -lnotify

GUI_HASH_SOURCES = src/hashes/md5.c src/hashes/sha1.c src/hashes/sha256.c src/hashes/sha3-256.c src/hashes/sha512.c src/hashes/sha3-512.c src/hashes/whirlpool.c src/hashes/gost94.c
GUI_SOURCES = src/main.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c src/hmac.c src/delete_input_file.c src/random_write.c src/zero_write.c src/prepare_text.c src/encrypt_text.c

all: polcrypt
install:
	test -s polcrypt && cp -v polcrypt /usr/bin/ || echo "--> GUI not built, please type make before make install"
	test -s po/it.mo && cp -v po/it.mo /usr/share/locale/it/LC_MESSAGES/polcrypt.mo || echo "--> Italian language not copied"
	cp -v polcrypt.png /usr/share/icons/hicolor/128x128/apps/

polcrypt: $(GUI_SOURCES)
	$(CC) $(CFLAGS) $(GUI_SOURCES) $(GUI_HASH_SOURCES) -o polcrypt $(LDFLAGS) `pkg-config --cflags --libs gtk+-3.0`

