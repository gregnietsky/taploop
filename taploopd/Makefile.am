ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -g -Wall -Werror -I./include -I../framework/include

sbin_PROGRAMS = taploopd
bin_PROGRAMS = taploop

taploopd_SOURCES = taploop.c util.c vlan.c tlsock.c clientserv.c packet.c
taploopd_LDADD = ../framework/libframework-0.1.la

taploop_SOURCES = tapclient.c
