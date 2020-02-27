#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(isout, 1.0.0, i.sshe@foxmail.com)
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
LT_INIT
# LT_INIT([shared disable-static])
# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

# Checks for libraries.
#AC_CHECK_LIB([ssl], [SSL_library_init], [],
#             [AC_MSG_FAILURE([can't find openssl ssl lib])])
#AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
#             [AC_MSG_FAILURE([can't find openssl crypto lib])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset])

AC_CONFIG_FILES([Makefile
                lib/Makefile
                src/Makefile
                test/Makefile
                test/protocol/Makefile
                test/protocol/isout/Makefile])

# openssl暂未用到，先去掉
# ISOUT_CONFIG_FILES([lib/openssl/config])

AC_CONFIG_SUBDIRS([lib/libevent
                lib/libisshe])

AC_OUTPUT
