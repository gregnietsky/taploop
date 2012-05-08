ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include

if FRAMEWORK_INSTALL
       lib_LTLIBRARIES = libframework-0.1.la
       include_HEADERS = include/framework.h
else
       noinst_LTLIBRARIES = libframework-0.1.la
endif

libframework_0_1_la_SOURCES = refobj.c lookup3.c thread.c main.c unixsock.c util.c radutil.c iputil.c
