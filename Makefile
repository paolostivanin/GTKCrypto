CFLAGS = -Wall -Wextra -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security -fstack-protector-all -fmudflap -lmudflap -fPIE
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lcrypto -lgcrypt
SOURCES = src/aes256cbc.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c src/hmac.c
all: polcrypt
polcrypt: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o polcrypt $(LDFLAGS)

