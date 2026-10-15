ifdef DEBUG
CXXFLAGS ?= -g -DDEBUG
else
CXXFLAGS ?= -O3
endif

PREFIX  ?= /usr/local
CXX     ?= g++
GZIP    ?= /bin/gzip
MANDIR  ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR ?= ${DESTDIR}${PREFIX}/sbin
PKG_CONFIG ?= pkg-config


# Everything except the entry point. The unit tests link against these, so
# they must not contain main().
LIB_OBJS = src/logger.o src/iface.o src/proxy.o src/address.o \
           src/rule.o src/session.o src/conf.o src/route.o

OBJS     = ${LIB_OBJS} src/ndppd.o

ifdef WITH_ND_NETLINK
  LIBS     = `${PKG_CONFIG} --libs glib-2.0 libnl-3.0 libnl-route-3.0` -pthread
  CPPFLAGS = `${PKG_CONFIG} --cflags glib-2.0 libnl-3.0 libnl-route-3.0`
  OBJ      = ${OBJ} src/nd-netlink.o
endif

TEST_SRCS = test/unit/main.cc \
            test/unit/test_address.cc \
            test/unit/test_conf.cc \
            test/unit/test_ptr.cc \
            test/unit/test_route.cc

TEST_OBJS = ${TEST_SRCS:.cc=.o}
TEST_BIN  = test/unit/ndppd-unit-tests

all: ndppd ndppd.1.gz ndppd.conf.5.gz

install: all
	mkdir -p ${SBINDIR} ${MANDIR} ${MANDIR}/man1 ${MANDIR}/man5
	cp ndppd ${SBINDIR}
	chmod +x ${SBINDIR}/ndppd
	cp ndppd.1.gz ${MANDIR}/man1
	cp ndppd.conf.5.gz ${MANDIR}/man5

ndppd.1.gz:
	${GZIP} < ndppd.1 > ndppd.1.gz

ndppd.conf.5.gz:
	${GZIP} < ndppd.conf.5 > ndppd.conf.5.gz

ndppd: ${OBJS}
	${CXX} -o ndppd ${LDFLAGS} ${OBJS} ${LIBS}

nd-proxy: nd-proxy.c
	${CXX} -o nd-proxy -Wall -Werror ${LDFLAGS} `${PKG_CONFIG} --cflags glib-2.0` nd-proxy.c `${PKG_CONFIG} --libs glib-2.0`

.cc.o:
	${CXX} -c ${CPPFLAGS} $(CXXFLAGS) -o $@ $<

# --- tests ---------------------------------------------------------------
#
# `make check` runs both layers. See test/README.md.
#
#   check-unit         pure functions; no privileges, no network
#   check-integration  a real daemon in unprivileged network namespaces
#
# NDPPD_TEST_SRCDIR lets the tests find checked-in fixtures and the shipped
# ndppd.conf-dist regardless of where they are run from.

test/unit/%.o: test/unit/%.cc
	${CXX} -c ${CPPFLAGS} $(CXXFLAGS) -I src -I test/unit \
	    -DNDPPD_TEST_SRCDIR='"$(CURDIR)"' -o $@ $<

${TEST_BIN}: ${TEST_OBJS} ${LIB_OBJS}
	${CXX} -o $@ ${LDFLAGS} ${TEST_OBJS} ${LIB_OBJS} ${LIBS}

check-unit: ${TEST_BIN}
	./${TEST_BIN}

check-integration: ndppd
	./test/integration/run.sh

check: check-unit check-integration

test: check

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.1.gz ${OBJS} nd-proxy \
	      ${TEST_OBJS} ${TEST_BIN}

.PHONY: all install clean check check-unit check-integration test
