CFLAGS = -Wall -Wextra -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security -fstack-protector-all -fPIE -Wno-unused-result
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt
HASH_SOURCES = src/hash-algo/md5.c src/hash-algo/sha256.c src/hash-algo/sha512.c src/hash-algo/whirlpool.c src/hash-algo/rmd160.c src/hash-algo/sha1.c 
SOURCES = src/main.c src/check_pkcs7.c src/encrypt_file.c src/decrypt_file.c src/hmac.c src/delete_input_file.c src/random_write.c src/zero_write.c

GUI_HASH_SOURCES = src/gtk3/hashes/md5.c src/gtk3/hashes/sha1.c src/gtk3/hashes/sha256.c src/gtk3/hashes/sha512.c src/gtk3/hashes/whirlpool.c src/gtk3/hashes/rmd160.c
GUI_SOURCES = src/gtk3/main-gui.c src/gtk3/check_pkcs7.c src/gtk3/encrypt_file_gui.c src/gtk3/decrypt_file_gui.c src/gtk3/hmac-gui.c src/gtk3/delete_input_file.c src/gtk3/random_write.c src/gtk3/zero_write.c

all: polcrypt-cli polcrypt-gui
cli: polcrypt-cli
gui: polcrypt-gui

polcrypt-cli: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(HASH_SOURCES) -o polcrypt-cli $(LDFLAGS)

polcrypt-gui: $(SOURCES)
	$(CC) $(CFLAGS) $(GUI_SOURCES) $(GUI_HASH_SOURCES) -o polcrypt-gui $(LDFLAGS) `pkg-config --cflags --libs gtk+-3.0` $(LDFLAGS)
	
