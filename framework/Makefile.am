ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include
SUBDIRS = libnetlink

if FRAMEWORK_INSTALL
       lib_LTLIBRARIES = libframework.la
       includeinstdir = $(oldincludedir)/framework
       includeinst_DATA = include/framework.h
       noinst_LTLIBRARIES = libnlclient.la
else
       noinst_LTLIBRARIES = libframework.la libnlclient.la
endif

libnlclient_la_SOURCES = netlink.c
libnlclient_la_CFLAGS = -I./include

libframework_la_SOURCES = refobj.c lookup3.c thread.c main.c unixsock.c util.c radius.c iputil.c sslutil.c interface.c config.c
libframework_la_LIBADD = ./libnlclient.la ./libnetlink/libnetlink.la
libframework_la_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
libframework_la_LDFLAGS = -version-info 1:0:1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = framework.pc
