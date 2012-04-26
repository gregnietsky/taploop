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

# Checks for libraries.
#Framework changes
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
LT_INIT()

AC_CHECK_LIB([pthread], [pthread_create])

AC_ARG_WITH([system-framework], AS_HELP_STRING([--with-system-framework], [Use the system framework not the packaged version]))
AC_ARG_ENABLE([framework-install], AS_HELP_STRING([--enable-framework-install], [Install the framework library please note this superseeds the --with-system-framewok option.]))
AC_ARG_ENABLE([dev-mode], AS_HELP_STRING([--enable-dev-mode], [Developer mode -g -Wall -Werror -pedantic-errors]))
AC_ARG_ENABLE([world-peace], AS_HELP_STRING([--enable-world-peace], [Yeah right .....]))

AS_IF([test "$enable_framework_install" != "yes"],
	AS_IF([test "$with_system_framework" = "yes"],
		[AC_CHECK_LIB([framework-0.1], [framework_mkthread])]))

if test "$ac_cv_lib_framework_0_1_framework_mkthread" != yes ; then
 FRAMEWORK_INCL="-I../framework/include"
 FRAMEWORK_LIBS="../framework/libframework-0.1.la"
fi;

if test "$enable_dev_mode" = "yes" ; then
 DEVELOPER_CFLAGS="-g -Wall -Werror -pedantic-errors"
fi;

AC_SUBST(FRAMEWORK_LIBS)
AC_SUBST(FRAMEWORK_INCL)
AC_SUBST(FRAMEWORK_SOURCES)
AC_SUBST(DEVELOPER_CFLAGS)

AM_CONDITIONAL([FRAMEWORK_INSTALL], [test "$enable_framework_install" = yes])
AM_CONDITIONAL([FRAMEWORK_SYSTEM], [test "$ac_cv_lib_framework_0_1_framework_mkthread" != yes])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h unistd.h])

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
                 src/Makefile])
AC_OUTPUT
