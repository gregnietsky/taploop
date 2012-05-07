ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(FRAMEWORK_INCL) $(DEVELOPER_CFLAGS)
EXTRA_DIST = include

bin_PROGRAMS = taploop
taploop_SOURCES = tapclient.c

sbin_PROGRAMS = taploopd
taploopd_SOURCES = taploop.c util.c vlan.c tlsock.c clientserv.c packet.c radius.c
taploopd_LDADD = $(FRAMEWORK_LIBS)
