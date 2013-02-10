CC = clang
CFLAGS = -Wall -Wextra -D_FORTIFY_SOURCE=2 -O2 -Wformat-security
LDFLAGS = -lcrypto -lgcrypt
SOURCES = src/aes256cbc.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c
all: polcrypt
polcrypt: src/aes256cbc.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c
	$(CC) $(CFLAGS) $(SOURCES) -o polcrypt $(LDFLAGS) `pkg-config --cflags --libs glib-2.0`

