UNAME := $(shell uname -s)

I2PD_PATH := i2pd
I2PD_LIB := libi2pd.a
BINARY := i2pbox

LIBI2PD_PATH := $(I2PD_PATH)/libi2pd
LIBI2PD_CLIENT_PATH := $(I2PD_PATH)/libi2pd_client

CXX ?= g++
CXXFLAGS := -Wall -std=c++17 -O2
INCFLAGS := -I$(LIBI2PD_PATH) -I$(LIBI2PD_CLIENT_PATH)
DEFINES := -DOPENSSL_SUPPRESS_DEPRECATED

LDFLAGS :=
LDLIBS := $(I2PD_PATH)/$(I2PD_LIB) -lboost_program_options$(BOOST_SUFFIX) -lssl -lcrypto -lz

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

all: $(I2PD_LIB) $(BINARY)

$(BINARY): $(OBJS) $(I2PD_LIB)
	$(CXX) -o $@ $(LDFLAGS) $(OBJS) $(LDLIBS)

%.o: %.cpp $(I2PD_LIB)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCFLAGS) -c -o $@ $<

$(I2PD_LIB):
	$(MAKE) -C $(I2PD_PATH) mk_obj_dir $(I2PD_LIB)

clean-i2pd:
	$(MAKE) -C $(I2PD_PATH) clean

clean-obj:
	rm -f $(OBJS)

clean-bin:
	rm -f $(BINARY)

clean: clean-i2pd clean-obj clean-bin

strip:
	strip $(BINARY)

count:
	wc *.cpp *.h *.hpp common/*.hpp common/*.h 2>/dev/null

install: $(BINARY)
	install -m 755 $(BINARY) /usr/local/bin/

.PHONY: all clean clean-i2pd clean-obj clean-bin strip count install
