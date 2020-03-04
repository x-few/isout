AM_CPPFLAGS = -g -O2 \
	-I$(top_srcdir)/lib/libisshe/src/base \
	-I$(top_srcdir)/lib/libisshe/src/crypto \
	-I$(top_srcdir)/lib/libisshe/src/json \
	-I$(top_srcdir)/lib/libevent/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/base \
	-I$(top_srcdir)/src/protocol/isout \
	-I$(top_srcdir)/src/roles/imaster \
	-I$(top_srcdir)/src/roles/isocks \
	-I$(top_srcdir)/src/roles/iproxy

LDADD = \
	${top_builddir}/lib/libisshe/src/libisshe.a


bin_PROGRAMS = \
	test_isout_encode_decode.out


test_isout_encode_decode_out_SOURCES = \
	test_isout_encode_decode.c \
	../../../src/protocol/isout/isout_decode.c \
	../../../src/protocol/isout/isout_encode.c


