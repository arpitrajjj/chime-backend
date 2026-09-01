# Chime backend - self-contained build (SQLite is vendored)
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE
CFLAGS  += -Isrc -Ivendor/sqlite
CFLAGS  += -DSQLITE_OMIT_LOAD_EXTENSION=1 -DSQLITE_DQS=0 -DSQLITE_THREADSAFE=1
LDFLAGS +=
LIBS    := -pthread -lm -ldl

SRC := $(wildcard src/*.c) vendor/sqlite/sqlite3.c
HDR := src/chime.h

all: chime-server

chime-server: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -rdynamic -o $@ $(SRC) $(LDFLAGS) $(LIBS)

# fully static binary
static: clean
	$(CC) $(CFLAGS) -static -o chime-server $(SRC) $(LDFLAGS) $(LIBS)

debug: clean
	$(CC) -O0 -g -Wall -Wextra -std=c11 -D_GNU_SOURCE -Isrc -Ivendor/sqlite \
	      -DSQLITE_OMIT_LOAD_EXTENSION=1 -DSQLITE_DQS=0 \
	      -fsanitize=address,undefined -rdynamic \
	      -o chime-server $(SRC) -pthread -lm -ldl

selftest:
	$(CC) $(CFLAGS) scripts/crypto_selftest.c src/sha256.c src/util.c src/log.c \
	      -o cryptotest $(LDFLAGS) $(LIBS)
	./cryptotest

test: chime-server
	./scripts/smoke.sh

clean:
	rm -f chime-server cryptotest
	rm -rf data-test

.PHONY: all static debug selftest test clean
