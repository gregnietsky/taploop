ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -g -Wall -Werror -I./include -I../framework/include

bin_PROGRAMS = taploopd
taploopd_SOURCES = taploop.c util.c vlan.c tlsock.c clientserv.c packet.c
taploopd_LDADD = ../framework/libframework-0.1.la
