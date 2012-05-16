ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include

if FRAMEWORK_INSTALL
       lib_LTLIBRARIES = libframework.la
       include_HEADERS = include/framework.h
else
       noinst_LTLIBRARIES = libframework.la
endif

noinst_LIBRARIES = libnetlink.a
libnetlink_a_SOURCES = netlink.c
libnetlink_a_CFLAGS = -I./include

libframework_la_SOURCES = refobj.c lookup3.c thread.c main.c unixsock.c util.c radius.c iputil.c sslutil.c interface.c config.c
libframework_la_LIBADD = libnetlink.a
libframework_la_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
libframework_la_LDFLAGS = -version-info 1:0:1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = framework.pc
