#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([taploop],[0.1],[gregory@distrotech.co.za])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([framework/thread.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

LT_INIT()

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
AC_CHECK_LIB(pthread, pthread_create)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h unistd.h])

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
                 taploopd/Makefile])
AC_OUTPUT
