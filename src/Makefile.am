AM_CPPFLAGS = \
	-I$(top_srcdir)/lib/libisshe/include/core \
	-I$(top_srcdir)/lib/libisshe/include/crypto \
	-I$(top_srcdir)/lib/libevent/include \
	-I$(top_srcdir)/src

LDADD = \
	${top_builddir}/lib/libisshe/src/libisshe.a \
	${top_builddir}/lib/libevent/libevent.la

bin_PROGRAMS = \
	isshe_proxy_server \
	isshe_socks_parser

isshe_proxy_server_SOURCES = \
	isshe_config_parser.c \
	isshe_proxy_server.c \
	isshe_socks_common.c \
	isshe_socks_protocol.c

isshe_socks_parser_SOURCES = \
	isshe_socks_parser.c \
	isshe_config_parser.c \
	isshe_socks_common.c \
	isshe_socks_protocol.c