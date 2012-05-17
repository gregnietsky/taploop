ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(DEVELOPER_CFLAGS)

noinst_LTLIBRARIES = libnetlink.la
libnetlink_la_SOURCES = libnetlink.c utils.c rt_names.c ll_types.c ll_proto.c ll_addr.c inet_proto.c ipx_ntop.c dnet_ntop.c dnet_pton.c
libnetlink_la_CFLAGS = -I./include

includeinstdir = $(oldincludedir)/framework
includeinst_DATA = include/libnetlink.h
