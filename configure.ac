#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([goldy], [0.0.3], [https://github.com/teamorchard/goldy/issues])

AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(auto)
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE
AM_DEP_TRACK

#MNEDTLS_REQUIRED=2.4.0

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen])

LT_CONFIG_LTDL_DIR([libltdl])
LTDL_INIT

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_ASSERT
AC_HEADER_STDC

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_CHECK_FUNCS([malloc memset socket posix_memalign])

AC_DISABLE_STATIC
AC_DISABLE_SHARED
LT_INIT([dlopen])

dnl Checks for TLS
AX_TLS([:], [:])

AC_CHECK_HEADERS([ev.h], [], [])
AC_CHECK_LIB([ev], [ev_loop_destroy], [LIBS="-lev $LIBS"], [AC_MSG_ERROR([Could not find libev.])])

# Check for mbedtls libs using m4 macro
MBEDTLS

dnl Enable and check for degug flags
AC_ARG_ENABLE([debug],
[  --enable-debug    Turn on debugging],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],[debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_CONFIG_FILES([Makefile])
#                 test/Makefile])
AC_OUTPUT
