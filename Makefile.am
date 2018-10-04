SUBDIRS = . test

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

LOCAL_CFLAGS = -Wall -W -Wdeclaration-after-statement

if DEBUG
DBG = -g3
endif

EXTRA_DIST    = autogen.sh \
                README.md \
                CLA-Corporate.txt \
                CLA-Individual.txt \
                CONTRIBUTING.md \
                LICENSE

export top_srcdir


AM_CPPFLAGS   = -I$(includedir) -D_FILE_OFFSET_BITS=64

AM_CFLAGS     = $(DBG) $(LOCAL_CFLAGS) \
                -fno-strict-aliasing

AM_LDFLAGS    = -g $(DBG)

goldy_LDADD   = -lm -lz

goldy_client_LDADD  = -lm -lz

bin_PROGRAMS  = goldy goldy-client

goldy_SOURCES = daemonize.c \
                daemonize.h \
                goldy.c \
                goldy.h \
                log.c \
                log.h \
                utlist.h

goldy_client_SOURCES = goldy-client.c \
                       daemonize.c \
                       daemonize.h \
                       goldy.h \
                       log.c \
                       log.h
