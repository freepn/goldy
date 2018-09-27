AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

LOCAL_CFLAGS = -Wall -W -Wdeclaration-after-statement

if DEBUG
DBG = -g3
endif

AM_CPPFLAGS   = -I$(includedir) -D_FILE_OFFSET_BITS=64

AM_CFLAGS     = $(DBG) $(LOCAL_CFLAGS) \
                -fno-strict-aliasing \
                $(MBEDTLS_CFLAGS) \
                $(LIBEV_CFLAGS)

AM_LDFLAGS    = $(MBEDTLS_LIBS) $(LIBEV_LIBS) -lm -lz $(DBG)

bin_PROGRAMS  = goldy

goldy_SOURCES = daemonize.c \
                daemonize.h \
                goldy.c \
                goldy.h \
                log.c \
                log.h \
                utlist.h

