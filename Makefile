CC = gcc
#CC = clang

CFLAGS = -Wall -Wextra -O2 -Wformat=2 -fstack-protector-all -fPIE -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align $(shell pkg-config --cflags gtk+-3.0)
DFLAGS = -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2

#delete -Wno-cast-qual after glib-2.44.1 has been released
NOFLAGS = -Wno-missing-field-initializers -Wno-return-type -Wno-cast-qual

LDFLAGS = -Wl,-z,now -Wl,-z,relro

LIBS = -lgcrypt -lnettle -lnotify $(shell pkg-config --libs gtk+-3.0)

SOURCES = $(wildcard src/*.c)
OBJS = ${SOURCES:.c=.o}

PROG = gtkcrypto

.SUFFIXES:.c .o

.c.o:
	$(CC) -c $(CFLAGS) $(NOFLAGS) $(DFLAGS) $< -o $@

all: $(PROG)


$(PROG) : $(OBJS)
	$(CC) $(CFLAGS) $(NOFLAGS) $(DFLAGS) $(OBJS) -o $@ $(LIBS)


.PHONY: clean

clean :
	rm -f $(PROG) $(OBJS)


install:
	mkdir -v /usr/share/gtkcrypto
	test -s gtkcrypto.desktop && cp -v gtkcrypto.desktop /usr/share/applications/ || echo "Desktop file not copied"
	test -s gtkcrypto && cp -v gtkcrypto /usr/bin/ || echo "--> GUI not built, please type make before make install"
	test -s po/it.mo && cp -v po/it.mo /usr/share/locale/it/LC_MESSAGES/gtkcrypto.mo || echo "--> Italian language not installed"
	test -s COPYING && cp -v COPYING /usr/share/gtkcrypto/
	cp -v gtkcrypto.png /usr/share/pixmaps/


uninstall:
	rm -vr /usr/share/gtkcrypto
	rm -v /usr/bin/gtkcrypto
	rm -v /usr/share/applications/gtkcrypto.desktop
