CC       = /usr/bin/gcc
CFLAGS   = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -O3 -fomit-frame-pointer -march=native
NISTFLAGS = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99
RM       = /bin/rm

# Allow external overrides
CPPFLAGS ?=
LDFLAGS  ?=
LIBS     ?=

all: test/PQCgenKAT_kem \
     test/test_kex \
     test/kem

SOURCES = pack_unpack.c poly.c fips202.c verify.c cbd.c SABER_indcpa.c kem.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h

test/test_kex: $(SOURCES) $(HEADERS) rng.o test/test_kex.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES) rng.o test/test_kex.c $(LDFLAGS) $(LIBS)

test/PQCgenKAT_kem: $(SOURCES) $(HEADERS) rng.o test/PQCgenKAT_kem.c
	$(CC) $(CPPFLAGS) $(NISTFLAGS) -o $@ $(SOURCES) rng.o test/PQCgenKAT_kem.c $(LDFLAGS) $(LIBS)

test/kem: $(SOURCES) $(HEADERS) rng.o test/kem.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SOURCES) rng.o test/kem.c $(LDFLAGS) $(LIBS)

rng.o: rng.c
	$(CC) $(CPPFLAGS) $(NISTFLAGS) -c rng.c -o $@

.PHONY: clean test

test:
	./test/test_kex
	./test/PQCgenKAT_kem
	./test/kem

clean:
	-$(RM) -f *.o
	-$(RM) -rf test/test_kex
	-$(RM) -rf test/kem
	-$(RM) -rf test/PQCgenKAT_kem
	-$(RM) -f *.req
	-$(RM) -f *.rsp
