# Host unit tests for libapmon (no cmake needed).
# CRYPTO: mbedtls (default) or openssl; run "make check-all" for both.
# MBEDTLS_DIR: an mbedtls 3.6 tree built with "make lib"; unset = system libmbedcrypto.
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu99 -Wall -Wextra -Werror -I../src/lib -I.
CRYPTO ?= mbedtls
LIB_SRC := $(filter-out ../src/lib/crypto_%.c,$(wildcard ../src/lib/*.c)) ../src/lib/crypto_$(CRYPTO).c

ifeq ($(CRYPTO),openssl)
LDLIBS += -lcrypto
else ifdef MBEDTLS_DIR
CFLAGS += -I$(MBEDTLS_DIR)/include
LDLIBS += $(MBEDTLS_DIR)/library/libmbedcrypto.a
else
LDLIBS += -lmbedcrypto
endif
LDLIBS += -lm

test_apmon: test_apmon.c $(LIB_SRC) vectors/vectors.h
	$(CC) $(CFLAGS) -o $@ test_apmon.c $(LIB_SRC) $(LDLIBS)

test_apmon_openssl: test_apmon.c $(wildcard ../src/lib/*.c) vectors/vectors.h
	$(MAKE) CRYPTO=openssl test_apmon_build OUT=$@

test_apmon_build:
	$(CC) $(CFLAGS) -o $(OUT) test_apmon.c $(LIB_SRC) $(LDLIBS)

check: test_apmon
	./test_apmon

check-all: test_apmon test_apmon_openssl
	./test_apmon
	./test_apmon_openssl

clean:
	rm -f test_apmon test_apmon_openssl

.PHONY: check check-all clean test_apmon_build
