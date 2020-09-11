#
# Makefile
#
# Copyright (C) 2010 Alfred E. Heggestad
#

PROJECT	  := srtperf
VERSION   := 0.5.0


ifeq ($(LIBRE_MK),)
LIBRE_MK  := $(shell [ -f /usr/share/re/re.mk ] && \
	echo "/usr/share/re/re.mk")
endif
ifeq ($(LIBRE_MK),)
LIBRE_MK  := $(shell [ -f /usr/local/share/re/re.mk ] && \
	echo "/usr/local/share/re/re.mk")
endif

include $(LIBRE_MK)


HAVE_LIBSRTP := $(shell [ -f $(SYSROOT)/include/srtp/srtp.h ] || \
	[ -f $(SYSROOT)/local/include/srtp/srtp.h ] || \
	[ -f $(SYSROOT_ALT)/include/srtp/srtp.h ] && echo "yes")


HAVE_LIBSRTP2 := $(shell [ -f $(SYSROOT)/include/srtp2/srtp.h ] || \
	[ -f $(SYSROOT)/local/include/srtp2/srtp.h ] || \
	[ -f $(SYSROOT_ALT)/include/srtp2/srtp.h ] && echo "yes")


INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  := /usr/local
else
PREFIX  := /usr
endif
BINDIR	:= $(PREFIX)/bin
CFLAGS	+= -g -Wall -I$(LIBRE_INC)
LIBS	+= -L/usr/local/lib -lm

#
# libsrtp2 takes precedence over libsrtp
#
ifneq ($(HAVE_LIBSRTP2),)
CFLAGS	+= -DHAVE_LIBSRTP -DLIBSRTP_VERSION=2
LIBS	+= -lsrtp2
else

ifneq ($(HAVE_LIBSRTP),)
CFLAGS	+= -DHAVE_LIBSRTP -DLIBSRTP_VERSION=1
LIBS	+= -lsrtp
endif

endif


BIN	:= $(PROJECT)$(BIN_SUFFIX)
APP_MK	:= src/srcs.mk

include $(APP_MK)

OBJS	?= $(patsubst %.c,$(BUILD)/src/%.o,$(SRCS))

all: $(BIN)

-include $(OBJS:.o=.d)

$(BIN): $(OBJS)
	@echo "  LD      $@"
ifneq ($(GPROF),)
	@$(LD) $(LFLAGS) $^ ../re/libre.a $(LIBS) -o $@
else
	@$(LD) $(LFLAGS) $^ -L$(LIBRE_SO) -lre $(LIBS) -o $@
endif


$(BUILD)/%.o: %.c $(BUILD) Makefile $(APP_MK)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -o $@ -c $< $(DFLAGS)

$(BUILD): Makefile
	@mkdir -p $(BUILD)/src
	@touch $@

clean:
	@rm -rf $(BIN) $(BUILD)

install: $(BIN)
	@mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)


dump:
	@echo "HAVE_LIBSRTP:     $(HAVE_LIBSRTP)"
	@echo "HAVE_LIBSRTP2:    $(HAVE_LIBSRTP2)"
