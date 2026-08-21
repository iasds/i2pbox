UNAME := $(shell uname -s)

# The -include of *.d files below would otherwise make the first parsed rule
# (main.o from the generated dependency files) the default goal, so a bare
# `make` would stop after compiling main.o. Pin the default goal to `all`.
.DEFAULT_GOAL := all

I2PD_PATH := i2pd
I2PD_LIB := $(I2PD_PATH)/libi2pd.a
BINARY := i2pbox
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
I2PD_VERSION := $(shell git -C $(I2PD_PATH) describe --tags --always --dirty 2>/dev/null || echo unknown)

LIBI2PD_PATH := $(I2PD_PATH)/libi2pd
LIBI2PD_CLIENT_PATH := $(I2PD_PATH)/libi2pd_client

CXX ?= g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 \
	-fstack-protector-strong -D_FORTIFY_SOURCE=2 \
	-fPIE -Wformat -Wformat-security -Wno-unused-parameter
INCFLAGS := -I$(LIBI2PD_PATH) -I$(LIBI2PD_CLIENT_PATH)
DEFINES := -DOPENSSL_SUPPRESS_DEPRECATED -DI2PBOX_VERSION=\"$(VERSION)\" -DI2PD_VERSION=\"$(I2PD_VERSION)\"

LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie
LDLIBS := $(I2PD_LIB) -lboost_program_options$(BOOST_SUFFIX) -lssl -lcrypto -lz

ifeq ($(UNAME),Linux)
    CXXFLAGS += -g
    LDLIBS += -lrt -lpthread
else ifeq ($(UNAME),Darwin)
    CXXFLAGS += -g
    LDLIBS += -lpthread
    ifeq ($(shell test -d /opt/homebrew && echo "true"),true)
        BREW_PREFIX := /opt/homebrew
    else
        BREW_PREFIX := /usr/local
    endif
    INCFLAGS += -I$(BREW_PREFIX)/include -I$(BREW_PREFIX)/opt/openssl@3/include
    LDFLAGS += -L$(BREW_PREFIX)/lib -L$(BREW_PREFIX)/opt/openssl@3/lib
    LDLIBS += -lboost_program_options
else ifeq ($(UNAME),FreeBSD)
    CXXFLAGS += -g
    LDLIBS += -lthr -lpthread
    LDFLAGS += -L/usr/local/lib
    INCFLAGS += -I/usr/local/include
else
    # Windows
    CXXFLAGS += -Os -fPIC -msse
    DEFINES += -DWIN32_LEAN_AND_MEAN
    LDFLAGS += -L/clang64/lib
    INCFLAGS += -I/clang64/include
    BOOST_SUFFIX =
    LDLIBS += -lwsock32 -lws2_32 -liphlpapi -lpthread
endif

# Object files for all tools + main
OBJS := main.o vain.o keygen.o keyinfo.o famtool.o routerinfo.o \
        regaddr.o regaddr_3ld.o i2pbase64.o offlinekeys.o b33address.o \
        regaddralias.o x25519.o verifyhost.o autoconf_i2pd.o

# Header dependency files (-MMD -MP), generated next to each object file
-include $(OBJS:.o=.d)

all: $(I2PD_LIB) $(BINARY)

$(BINARY): $(OBJS) $(I2PD_LIB)
	$(CXX) -o $@ $(LDFLAGS) $(OBJS) $(LDLIBS)

# Header dependencies are tracked by -MMD -MP (the .d files above). libi2pd.a
# is an order-only prerequisite so upstream submodule bumps (the weekly
# upstream-monitor) do not force a full recompile of every object file; only
# headers a translation unit actually includes trigger its rebuild. The link
# step below still depends on the library normally.
%.o: %.cpp | $(I2PD_LIB)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -MMD -MP -c -o $@ $<

$(I2PD_LIB):
	@if [ -f patches/i2pd-ecdsa-null-pkey.patch ] && ! grep -q "if (!m_PublicKey) return false" $(I2PD_PATH)/libi2pd/Signature.cpp 2>/dev/null; then \
	  echo "Applying patches/i2pd-ecdsa-null-pkey.patch (upstream i2pd#1997 null EVP_PKEY guard)..."; \
	  git -C $(I2PD_PATH) apply ../patches/i2pd-ecdsa-null-pkey.patch; \
	fi
	$(MAKE) -C $(I2PD_PATH) mk_obj_dir $(notdir $(I2PD_LIB))

clean-i2pd:
	$(MAKE) -C $(I2PD_PATH) clean

clean-obj:
	rm -f $(OBJS) $(OBJS:.o=.d)

clean-bin:
	rm -f $(BINARY)

clean: clean-i2pd clean-obj clean-bin
	rm -rf tests/gen_router_info dist/

clean-fuzz:
	rm -f oom-* crash-* timeout-* leak-* tests/fuzz/corpus/*/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]

strip:
	strip $(BINARY)

count:
	@wc *.cpp *.h *.hpp common/*.hpp common/*.h 2>/dev/null || true

bench: $(BINARY)
	@echo "== bench: keygen/keyinfo/i2pbase64 (100x) + vain smoke =="
	@tmpdir=$$(mktemp -d); \
	  echo -n "keygen 7 (100x): "; t0=$$(date +%s%N); for i in $$(seq 1 100); do ./$(BINARY) keygen $$tmpdir/k.$$i 7 >/dev/null 2>&1; done; t1=$$(date +%s%N); echo "$$(( (t1 - t0)/1000000 )) ms"; \
	  echo -n "keyinfo -v (100x): "; t0=$$(date +%s%N); for i in $$(seq 1 100); do ./$(BINARY) keyinfo -v $$tmpdir/k.1 >/dev/null 2>&1; done; t1=$$(date +%s%N); echo "$$(( (t1 - t0)/1000000 )) ms"; \
	  head -c 2048 /dev/urandom > $$tmpdir/rnd.bin; \
	  echo -n "i2pbase64 roundtrip (100x): "; t0=$$(date +%s%N); for i in $$(seq 1 100); do ./$(BINARY) i2pbase64 $$tmpdir/rnd.bin | ./$(BINARY) i2pbase64 -d >/dev/null; done; t1=$$(date +%s%N); echo "$$(( (t1 - t0)/1000000 )) ms"; \
	  echo -n "vain ej (smoke): "; timeout 5 ./$(BINARY) vain ej -t 2 -o $$tmpdir/vain.dat >/dev/null 2>&1 || true; test -s $$tmpdir/vain.dat && echo "ok" || echo "timeout/skip"; \
	  rm -rf $$tmpdir

test: $(BINARY) tests/gen_router_info
	./tests/test_cli.sh ./$(BINARY) ./tests/gen_router_info

interop: $(BINARY) tests/gen_router_info
	./tests/interop/run_interop.sh ./$(BINARY) "go rust java"

tests/gen_router_info: tests/gen_router_info.cpp $(I2PD_LIB)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< $(LDLIBS)

# --- fuzzing ---------------------------------------------------------------
# libFuzzer targets (clang): make fuzz-build, then run
# ./tests/fuzz/run_fuzz_smoke.sh [seconds]. Local gcc smoke (no libFuzzer):
# make fuzz-smoke.
FUZZ_CC ?= clang++
FUZZ_CXXFLAGS := -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined
FUZZ_STANDALONE := tests/fuzz/fuzz_base64_decode_standalone \
                   tests/fuzz/fuzz_b33address_standalone \
                   tests/fuzz/fuzz_keyinfo_standalone \
                   tests/fuzz/fuzz_routerinfo_standalone

fuzz-build: tests/fuzz/fuzz_base64_decode tests/fuzz/fuzz_b33address \
            tests/fuzz/fuzz_keyinfo tests/fuzz/fuzz_routerinfo

fuzz-smoke: $(FUZZ_STANDALONE)
	./tests/fuzz/run_smoke_local.sh

tests/fuzz/fuzz_base64_decode: tests/fuzz/fuzz_base64_decode.cpp $(I2PD_LIB) i2pbase64.o
	$(FUZZ_CC) $(FUZZ_CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< i2pbase64.o $(LDLIBS)

tests/fuzz/fuzz_b33address: tests/fuzz/fuzz_b33address.cpp $(I2PD_LIB)
	$(FUZZ_CC) $(FUZZ_CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< $(LDLIBS)

tests/fuzz/fuzz_keyinfo: tests/fuzz/fuzz_keyinfo.cpp $(I2PD_LIB)
	$(FUZZ_CC) $(FUZZ_CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< $(LDLIBS)

tests/fuzz/fuzz_routerinfo: tests/fuzz/fuzz_routerinfo.cpp $(I2PD_LIB)
	$(FUZZ_CC) $(FUZZ_CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< $(LDLIBS)

tests/fuzz/fuzz_base64_decode_standalone: tests/fuzz/fuzz_base64_decode.cpp tests/fuzz/standalone_main.cpp $(I2PD_LIB) i2pbase64.o
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< tests/fuzz/standalone_main.cpp i2pbase64.o $(LDLIBS)

tests/fuzz/fuzz_b33address_standalone: tests/fuzz/fuzz_b33address.cpp tests/fuzz/standalone_main.cpp $(I2PD_LIB)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< tests/fuzz/standalone_main.cpp $(LDLIBS)

tests/fuzz/fuzz_keyinfo_standalone: tests/fuzz/fuzz_keyinfo.cpp tests/fuzz/standalone_main.cpp $(I2PD_LIB)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< tests/fuzz/standalone_main.cpp $(LDLIBS)

tests/fuzz/fuzz_routerinfo_standalone: tests/fuzz/fuzz_routerinfo.cpp tests/fuzz/standalone_main.cpp $(I2PD_LIB)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -o $@ $< tests/fuzz/standalone_main.cpp $(LDLIBS)

# Installation layout (standard GNU dirs; override for packaging):
#   make install                          → /usr/local/bin/i2pbox
#   make install PREFIX=/usr              → /usr/bin/i2pbox
#   make install DESTDIR=/tmp/pkg PREFIX=/usr  → staging under /tmp/pkg
PREFIX ?= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/bin
DATADIR := $(DESTDIR)$(PREFIX)/share

install: $(BINARY)
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/i2pbox
	install -d $(DATADIR)/bash-completion/completions
	install -m 644 contrib/completion/bash/i2pbox $(DATADIR)/bash-completion/completions/i2pbox
	install -d $(DATADIR)/zsh/site-functions
	install -m 644 contrib/completion/zsh/_i2pbox $(DATADIR)/zsh/site-functions/_i2pbox

install-strip: install
	strip $(BINDIR)/i2pbox

uninstall:
	rm -f $(BINDIR)/i2pbox \
	      $(DATADIR)/bash-completion/completions/i2pbox \
	      $(DATADIR)/zsh/site-functions/_i2pbox

.PHONY: all clean clean-i2pd clean-obj clean-bin clean-fuzz strip count bench install install-strip uninstall test fuzz-build fuzz-smoke interop
