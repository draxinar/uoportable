CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -pedantic -Wno-attributes -O2 -std=c99
LDFLAGS = -Wl,--kill-at -Wl,--enable-stdcall-fixup

all: dsound.dll

dsound.dll: dsound.c dsound.def
	$(CC) $(CFLAGS) -shared -o $@ dsound.c dsound.def $(LDFLAGS)

clean:
	rm -f dsound.dll

.PHONY: all clean
