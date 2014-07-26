TMP_CF = -Wall -Wextra -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat=2 -fstack-protector-all -fPIE -Wno-unused-result -Wno-return-type -Wstrict-prototypes -Wno-unused-parameter -Wno-missing-field-initializers -Wno-maybe-uninitialized
#CFLAGS = -Wall -Wextra -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat=2 -fstack-protector-all -fPIE -Wno-unused-result -Wno-return-type -Wno-missing-field-initializers -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-align -Wcast-qual

LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt -lnettle -lnotify

SOURCES = src/*.c

OUT = polcrypt

all: polcrypt

install:
	mkdir -v /usr/share/polcrypt
	test -s polcrypt && cp -v polcrypt /usr/bin/ || echo "--> GUI not built, please type make before make install"
	test -s po/it.mo && cp -v po/it.mo /usr/share/locale/it/LC_MESSAGES/polcrypt.mo || echo "--> Italian language not installed"
	test -s src/main.css && cp -v src/main.css /usr/share/polcrypt/
	test -s LICENSE && cp -v LICENSE /usr/share/polcrypt/
	cp -v polcrypt.png /usr/share/icons/hicolor/128x128/apps/

uninstall:
	rm -vr /usr/share/polcrypt
	rm -v /usr/bin/polcrypt

$(OUT): $(SOURCES)
	$(CC) $(SOURCES) ${TMP_CF} -o $(OUT) $(LDFLAGS) `pkg-config --cflags --libs gtk+-3.0`
