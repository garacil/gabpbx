# Makefile for chan_sofia
#
# Builds chan_sofia.so against an installed Asterisk development tree and
# the Sofia-SIP library.
#
# Prerequisites
#   - Asterisk 1.8 headers installed (or source tree with a build done)
#   - Sofia-SIP development package (libsofia-sip-ua-dev / sofia-sip-devel)
#   - OpenSSL development package (for SHA-256 auth; optional but recommended)
#
# Usage
#   make              # build chan_sofia.so
#   make install      # copy to Asterisk modules directory
#   make clean        # remove build artifacts
#   make check        # run static-analysis lint (requires cppcheck)

# ── Tunable paths ──────────────────────────────────────────────────────────────
#
# Location of the Asterisk 1.8 source / build tree.
# Override with: make AST_SRC=/path/to/asterisk
AST_SRC    ?= /usr/src/asterisk

# Asterisk modules installation directory.
AST_MODDIR ?= $(shell asterisk -V 2>/dev/null | \
                  grep -oP '(?<=Asterisk )[0-9]+\.[0-9]+' | \
                  head -1 | xargs -I{} echo /usr/lib/asterisk/modules)
ifeq ($(AST_MODDIR),)
AST_MODDIR := /usr/lib/asterisk/modules
endif

# ── Tool detection ─────────────────────────────────────────────────────────────
CC         ?= gcc
PKG_CONFIG ?= pkg-config

# ── Sofia-SIP flags ────────────────────────────────────────────────────────────
SOFIA_CFLAGS  := $(shell $(PKG_CONFIG) --cflags sofia-sip-ua 2>/dev/null)
SOFIA_LDFLAGS := $(shell $(PKG_CONFIG) --libs   sofia-sip-ua 2>/dev/null)

ifeq ($(SOFIA_CFLAGS),)
  $(warning sofia-sip-ua not found via pkg-config; trying default paths)
  SOFIA_CFLAGS  := -I/usr/include/sofia-sip-1.12
  SOFIA_LDFLAGS := -lsofia-sip-ua
endif

# ── OpenSSL flags (for SHA-256) ────────────────────────────────────────────────
OPENSSL_CFLAGS  := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LDFLAGS := $(shell $(PKG_CONFIG) --libs   openssl 2>/dev/null)

ifneq ($(OPENSSL_CFLAGS),)
  EXTRA_CFLAGS  += -DHAVE_OPENSSL -DHAVE_OPENSSL_SHA $(OPENSSL_CFLAGS)
  EXTRA_LDFLAGS += $(OPENSSL_LDFLAGS)
endif

# ── Asterisk include path ──────────────────────────────────────────────────────
AST_CFLAGS := -I$(AST_SRC)/include

# ── Combined flags ─────────────────────────────────────────────────────────────
CFLAGS  := -O2 -g -fPIC -Wall -Wextra -Wno-unused-parameter \
           $(AST_CFLAGS) $(SOFIA_CFLAGS) $(EXTRA_CFLAGS) \
           -D_GNU_SOURCE -DASTERISK_GPL_KEY=\"GPL-2\"

LDFLAGS := -shared $(SOFIA_LDFLAGS) $(EXTRA_LDFLAGS)

# ── Sources ────────────────────────────────────────────────────────────────────
SRCS    := channels/chan_sofia.c
OBJS    := $(SRCS:.c=.o)
TARGET  := chan_sofia.so

# ── Default target ─────────────────────────────────────────────────────────────
.PHONY: all install clean check

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Built $@"

channels/%.o: channels/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Install ────────────────────────────────────────────────────────────────────
install: $(TARGET)
	install -D -m 0755 $(TARGET) $(AST_MODDIR)/$(TARGET)
	@if [ -f configs/sofia.conf.sample ] && \
	   [ ! -f /etc/asterisk/sofia.conf ]; then \
	    install -D -m 0640 configs/sofia.conf.sample \
	            /etc/asterisk/sofia.conf; \
	    echo "Installed sample config to /etc/asterisk/sofia.conf"; \
	fi
	@echo "Installed $(TARGET) to $(AST_MODDIR)"

# ── Static analysis ────────────────────────────────────────────────────────────
check:
	cppcheck --enable=all --suppress=missingIncludeSystem \
	         $(SOFIA_CFLAGS) $(AST_CFLAGS) \
	         channels/chan_sofia.c

# ── Clean ──────────────────────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(TARGET)