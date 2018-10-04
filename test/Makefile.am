LOCAL_CFLAGS = -Wall -W -Wdeclaration-after-statement

if DEBUG
DBG = -g3
endif

AM_CPPFLAGS   = -I$(includedir) -I$(top_srcdir) -D_FILE_OFFSET_BITS=64

AM_CFLAGS     = $(DBG) $(LOCAL_CFLAGS) \
                -fno-strict-aliasing

AM_LDFLAGS    = -g $(DBG)

BUILT_TESTS   = dtls_test_client \
                udp_test_server \
                send_one_dtls_packet

XFAIL_TESTS   = $(BUILT_TESTS)

TESTS = $(check_PROGRAMS)
check_PROGRAMS = $(BUILT_TESTS)

dtls_test_client_SOURCES = dtls_test_client.c
dtls_test_client_LDADD = -lm -lz
dtls_test_client_LDFLAGS = -Wl,--hash-style=gnu -no-install

udp_test_server_SOURCES = udp_test_server.c
udp_test_server_LDADD = -lm -lz
udp_test_server_LDFLAGS = -Wl,--hash-style=gnu -no-install

send_one_dtls_packet_SOURCES = send_one_dtls_packet.c
send_one_dtls_packet_LDADD = -lm -lz
send_one_dtls_packet_LDFLAGS = -Wl,--hash-style=gnu -no-install

check-local:
	./run_test.sh
