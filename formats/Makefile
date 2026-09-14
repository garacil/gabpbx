#
# GABpbx -- A telephony toolkit for Linux.
# 
# Makefile for file format modules
#
# Copyright (C) 1999-2006, Digium, Inc.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

-include $(ASTTOPDIR)/menuselect.makeopts $(ASTTOPDIR)/menuselect.makedeps

MODULE_PREFIX=format
MENUSELECT_CATEGORY=FORMATS
MENUSELECT_DESCRIPTION=Format Interpreters

all: _all

include $(ASTTOPDIR)/Makefile.moddir_rules

# format_ogg_opus queries the codec look-ahead (OPUS_GET_LOOKAHEAD) from libopus for the RFC 7845
# pre-skip; libogg comes from the <depend>ogg</depend> in its MODULEINFO. Same pkg-config pattern as
# codecs/Makefile uses for codec_opus.
format_ogg_opus.o: _ASTCFLAGS+=$(shell pkg-config --cflags opus 2>/dev/null)
format_ogg_opus.so: LIBS+=$(shell pkg-config --libs opus 2>/dev/null)
