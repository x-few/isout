AM_CPPFLAGS = -g -O2 \
	-I$(top_srcdir)/lib/libisshe/include/core \
	-I$(top_srcdir)/lib/libisshe/include/crypto \
	-I$(top_srcdir)/lib/libevent/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/base \
	-I$(top_srcdir)/src/roles/imaster \
	-I$(top_srcdir)/src/roles/isocks \
	-I$(top_srcdir)/src/roles/iproxy

LDADD = \
	${top_builddir}/lib/libisshe/src/libisshe.a \
	${top_builddir}/lib/libevent/libevent.la

bin_PROGRAMS = \
	isout.out

isout_out_SOURCES = \
	isout.c \
	base/iprotocol.c \
	base/ievent.c \
	base/iconfig.c \
	roles/imaster/imaster_process.c \
	roles/imaster/imaster_signal.c \
	roles/imaster/imaster.c \
	roles/isocks/isocks_config.c \
	roles/isocks/isocks_socks5.c \
	roles/isocks/isocks_event.c \
	roles/isocks/isocks_session.c \
	roles/isocks/isocks.c \
	roles/iproxy/iproxy.c
