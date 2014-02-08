CFLAGS = -Wall -Wextra -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security -fstack-protector-all -fPIE -Wno-unused-result -Wno-return-type -Wno-missing-field-initializers -g -ggdb
LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt

CLI_HASH_SOURCES = src/cli/hashes/md5.c src/cli/hashes/sha256.c src/cli/hashes/sha512.c src/cli/hashes/whirlpool.c src/cli/hashes/rmd160.c src/cli/hashes/sha1.c 
CLI_SOURCES = src/cli/main.c src/cli/check_pkcs7.c src/cli/encrypt_file.c src/cli/decrypt_file.c src/cli/hmac.c src/cli/delete_input_file.c src/cli/random_write.c src/cli/zero_write.c

GUI_HASH_SOURCES = src/gtk3/hashes/md5.c src/gtk3/hashes/sha1.c src/gtk3/hashes/sha256.c src/gtk3/hashes/sha512.c src/gtk3/hashes/whirlpool.c src/gtk3/hashes/rmd160.c
GUI_SOURCES = src/gtk3/main-gui.c src/gtk3/check_pkcs7.c src/gtk3/encrypt_file_gui.c src/gtk3/decrypt_file_gui.c src/gtk3/hmac-gui.c src/gtk3/delete_input_file.c src/gtk3/random_write.c src/gtk3/zero_write.c

all: polcrypt-cli polcrypt-gui
cli: polcrypt-cli
gui: polcrypt-gui
install:
	test -s polcrypt-cli && cp -v polcrypt-cli /usr/bin/ || echo "--> CLI not built"
	test -s polcrypt-gui && cp -v polcrypt-gui /usr/bin/ || echo "--> GUI not built"
	cp -v polcrypt.png /usr/share/icons/hicolor/128x128/apps/
	
polcrypt-cli: $(CLI_SOURCES)
	$(CC) $(CFLAGS) $(CLI_SOURCES) $(CLI_HASH_SOURCES) -o polcrypt-cli $(LDFLAGS)

polcrypt-gui: $(GUI_SOURCES)
	$(CC) $(CFLAGS) $(GUI_SOURCES) $(GUI_HASH_SOURCES) -o polcrypt-gui $(LDFLAGS) `pkg-config --cflags --libs gtk+-3.0`
	
