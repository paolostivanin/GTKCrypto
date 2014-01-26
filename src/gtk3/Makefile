CFLAGS = -Wall -Wextra -O2 -Wformat -Wformat-security -fstack-protector-all -fPIE -Wno-unused-result
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt
HASH_SOURCES = hashes/md5.c hashes/sha1.c hashes/sha256.c hashes/sha512.c hashes/whirlpool.c hashes/rmd160.c
SOURCES = main-gui.c check_pkcs7.c encrypt_file_gui.c decrypt_file_gui.c hmac-gui.c delete_input_file.c random_write.c zero_write.c
all: polcrypt
polcrypt: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(HASH_SOURCES) -o polcrypt `pkg-config --cflags --libs gtk+-3.0` $(LDFLAGS)

