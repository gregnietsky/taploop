AM_CFLAGS = -g -Wall -Werror -I./include $(FRAMEWORK_INCL)
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = taploop
taploop_SOURCES = tapclient.c

sbin_PROGRAMS = taploopd
taploopd_SOURCES = taploop.c util.c vlan.c tlsock.c clientserv.c packet.c
taploopd_LDADD = $(FRAMEWORK_LIBS)
