AM_CPPFLAGS = \
	-I$(top_srcdir)/lib/libisshe/include/core \
	-I$(top_srcdir)/lib/libisshe/include/crypto \
	-I$(top_srcdir)/lib/libevent/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/base \
	-I$(top_srcdir)/src/roles/imaster \
	-I$(top_srcdir)/src/roles/isocks


LDADD = \
	${top_builddir}/lib/libisshe/src/libisshe.a \
	${top_builddir}/lib/libevent/libevent.la

bin_PROGRAMS = \
	isout.out

isout_out_SOURCES = \
	isout.c \
	base/iconfig.c \
	base/ilog.c \
	roles/imaster/imaster_process.c \
	roles/imaster/imaster_signal.c \
	roles/imaster/imaster.c \
	roles/isocks/isocks.c
