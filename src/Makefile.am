ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I$(srcdir)/include $(DTSAPPLIB_CFLAGS) $(DEVELOPER_CFLAGS)
EXTRA_DIST = include

bin_PROGRAMS = taploop
taploop_SOURCES = tapclient.c
taploop_LDADD = $(DTSAPPLIB_LIBS)

sbin_PROGRAMS = taploopd
taploopd_SOURCES = taploop.c vlan.c tlsock.c clientserv.c packet.c radius.c
taploopd_LDADD = $(DTSAPPLIB_LIBS)
