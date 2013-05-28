CFLAGS = -Wall -Wextra -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security -fstack-protector-all -fmudflap -lmudflap -fPIE -Wno-unused-result
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt
<<<<<<< HEAD
SOURCES = src/aes256cbc.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c src/hmac.c src/delete_input_file.c src/random_write.c src/zero_write.c
HASH_SOURCES = src/hash-algo/md5.c src/hash-algo/sha256.c src/hash-algo/sha512.c src/hash-algo/whirlpool.c src/hash-algo/tiger.c src/hash-algo/tiger2.c src/hash-algo/rmd160.c src/hash-algo/sha1.c src/hash-algo/sha224.c src/hash-algo/sha384.c 
=======
SOURCES = src/main.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c src/hmac.c src/delete_input_file.c src/random_write.c src/zero_write.c
>>>>>>> master
all: polcrypt
polcrypt: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(HASH_SOURCES) -o polcrypt $(LDFLAGS)

