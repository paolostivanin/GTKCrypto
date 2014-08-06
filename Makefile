#CC = gcc
CC = clang

CFLAGS = -Wall -Wextra -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -Wformat=2 -fstack-protector-all -fPIE -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-align -Wcast-qual
NOFLAGS = -Wno-unused-result -Wno-missing-field-initializers -Wno-uninitialized -Wno-return-type

LDFLAGS = -Wl,-z,now -Wl,-z,relro -lgcrypt -lnettle -lnotify

SOURCES = src/*.c

OUT = polcrypt

all: polcrypt

install:
	mkdir -v /usr/share/polcrypt
	test -s polcrypt.desktop && cp -v polcrypt.desktop /usr/share/applications/ || echo "Desktop file not copied"
	test -s polcrypt && cp -v polcrypt /usr/bin/ || echo "--> GUI not built, please type make before make install"
	test -s po/it.mo && cp -v po/it.mo /usr/share/locale/it/LC_MESSAGES/polcrypt.mo || echo "--> Italian language not installed"
	test -s COPYING && cp -v COPYING /usr/share/polcrypt/
	cp -v polcrypt.png /usr/share/pixmaps/

uninstall:
	rm -vr /usr/share/polcrypt
	rm -v /usr/bin/polcrypt
	rm -v /usr/share/applications/polcrypt.desktop

$(OUT): $(SOURCES)
	$(CC) $(SOURCES) ${CFLAGS} $(NOFLAGS) -o $(OUT) $(LDFLAGS) `pkg-config --cflags --libs gtk+-3.0`
