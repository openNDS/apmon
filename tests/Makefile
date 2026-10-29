# Host unit tests for libapmon (no cmake needed).
# MBEDTLS_DIR: an mbedtls 3.6 tree built with "make lib"; unset = system libmbedcrypto.
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu99 -Wall -Wextra -Werror -I../src/lib -I.
LIB_SRC := $(wildcard ../src/lib/*.c)

ifdef MBEDTLS_DIR
CFLAGS += -I$(MBEDTLS_DIR)/include
LDLIBS += $(MBEDTLS_DIR)/library/libmbedcrypto.a
else
LDLIBS += -lmbedcrypto
endif
LDLIBS += -lm

test_apmon: test_apmon.c $(LIB_SRC) vectors/vectors.h
	$(CC) $(CFLAGS) -o $@ test_apmon.c $(LIB_SRC) $(LDLIBS)

check: test_apmon
	./test_apmon

clean:
	rm -f test_apmon

.PHONY: check clean
