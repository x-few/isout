AM_CPPFLAGS = \
	-I$(top_srcdir)/lib/libisshe/include \
	-I$(top_srcdir)/lib/libevent/include

LDADD = \
	${top_builddir}/lib/libisshe/src/libisshe.a

bin_PROGRAMS = \
	isshe_proxy_server \
	isshe_socks_parser

isshe_proxy_server_SOURCE = \
	isshe_config_parser.c \
	isshe_proxy_server.c \
	isshe_socks_common.c \
	isshe_socks_protocol.c

isshe_socks_parser_SOURCE = \
	isshe_socks_parser.c \
	isshe_config_parser.c \
	isshe_socks_common.c \
	isshe_socks_protocol.c