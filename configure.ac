#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([taploop],[0.1],[gregory@distrotech.co.za])
AC_CONFIG_SRCDIR([framework/thread.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_C_INLINE
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_HEADER_RESOLV
AC_TYPE_SSIZE_T

# Checks for libraries.
#Framework changes
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
LT_INIT()
AM_PROG_CC_C_O

AC_CHECK_LIB([pthread], [pthread_create])

AC_ARG_ENABLE([framework-install], AS_HELP_STRING([--enable-framework-install], [Install the framework library please note this superseeds the --with-system-framewok option.]))
AC_ARG_ENABLE([dev-mode], AS_HELP_STRING([--enable-dev-mode], [Developer mode -g -Wall -Werror -pedantic-errors]))
AC_ARG_ENABLE([world-peace], AS_HELP_STRING([--enable-world-peace], [Yeah right .....]))
AC_ARG_WITH([system-framework], AS_HELP_STRING([--with-system-framework], [Use the system framework not the packaged version]))

PKG_CHECK_MODULES(LIBFRAMEWORK, framework >= 0, [have_libframework=yes], [have_libframework=no])
AS_IF([test "x$enable_framework_install" != "xyes"],
	AS_IF([test "x$with_system_framework" = "xyes"],
		[AC_CHECK_LIB([framework], [framework_mkthread])]))

if (test "x$ac_cv_lib_framework_framework_mkthread" = "xyes") && (test "$have_libframework" = "xyes") ; then
   FRAMEWORK_INCL="$LIBFRAMEWORK_CFLAGS"
  else
   FRAMEWORK_INCL="-I../framework/include"
   FRAMEWORK_LIBS="../framework/libframework.la"
fi;

if test "x$enable_dev_mode" = "xyes" ; then
 DEVELOPER_CFLAGS="-g -Wall -Werror -pedantic-errors"
fi;

AC_SUBST(FRAMEWORK_LIBS)
AC_SUBST(FRAMEWORK_INCL)
AC_SUBST(FRAMEWORK_SOURCES)
AC_SUBST(DEVELOPER_CFLAGS)

AM_CONDITIONAL([FRAMEWORK_INSTALL], [test "x$enable_framework_install" = xyes])
AM_CONDITIONAL([FRAMEWORK_SYSTEM], [test "x$ac_cv_lib_framework_framework_mkthread" != "xyes"])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h unistd.h syslog.h sys/time.h netdb.h arpa/inet.h])

AC_CHECK_FUNCS([gethostbyaddr])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([strtoull])

AC_CHECK_LIB([ssl], [SSL_new])
AC_CHECK_LIB([crypto], [SHA512_Init])
AC_CHECK_LIB([uuid], [uuid_generate])

PKG_CHECK_MODULES(LIBNL3, libnl-3.0 >= 3.1, [have_libnl3=yes], [have_libnl3=no])
if (test "x${have_libnl3}" = "xyes"); then
        CFLAGS+=" $LIBNL3_CFLAGS"
        LIBS+=" $LIBNL3_LIBS"
fi

PKG_CHECK_MODULES(LIBNLROUTE3, libnl-route-3.0 >= 3.1, [have_libnlrt3=yes], [have_libnlrt3=no])
if (test "x${have_libnlrt3}" = "xyes"); then
        CFLAGS+=" $LIBNLROUTE3_CFLAGS"
        LIBS+=" $LIBNLROUTE3_LIBS"
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap select socket])

AC_CONFIG_FILES([Makefile
                 framework/Makefile
                 framework/libnetlink/Makefile
                 framework/framework.pc
                 src/Makefile])
AC_OUTPUT
