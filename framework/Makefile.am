ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include
SUBDIRS = libnetlink

if FRAMEWORK_INSTALL
       lib_LTLIBRARIES = libframework.la
       includeinstdir = $(oldincludedir)/framework
       includeinst_DATA = include/framework.h
else
       noinst_LTLIBRARIES = libframework.la
endif

libframework_la_SOURCES = refobj.c lookup3.c thread.c main.c unixsock.c util.c radius.c socket.c sslutil.c interface.c config.c \
                          iputil.c nf_queue.c nf_ctrack.c zlib.c rfc6296.c libxml2.c libxslt.c openldap.c

libframework_la_LIBADD = ./libnetlink/libnetlink.la $(XSLT_LIBS) $(XML_LIBS) $(LDAP_LIBS) $(LIBS)
libframework_la_CFLAGS = -I./include -I./libnetlink/include $(DEVELOPER_CFLAGS) $(XSLT_CFLAGS) $(XML_CFLAGS)
libframework_la_LDFLAGS = -version-info 1:0:1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = framework.pc
