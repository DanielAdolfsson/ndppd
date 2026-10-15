ifdef DEBUG
CFLAGS  ?= -g -DDEBUG
else
CFLAGS  ?= -Os
LDFLAGS ?= -s -w
endif

PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
CC          ?= gcc
GZIP        ?= /bin/gzip
MANDIR      ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR     ?= ${DESTDIR}${PREFIX}/sbin
ASCIIDOCTOR ?= /usr/bin/asciidoctor

# ndppd reads packets out of buffers it has declared __attribute__((packed)),
# and takes the address of fields inside them to hand to the checksum helper.
# Current GCC and Clang warn about that by default, and -Werror turns the
# warning into a failed build -- so without these the Makefile the README
# tells you to use has not compiled for several releases, even though
# CMakeLists.txt (which carries the same flags) has.
# Where ndppd looks for its configuration when -c is not given. This has to
# match ndppd(8) and ndppd.service, which passes no -c.
CPPFLAGS := ${CPPFLAGS} -DNDPPD_CONFIG_PATH='"${SYSCONFDIR}/ndppd.conf"'

CFLAGS := ${CFLAGS} -Werror -Wall -Wextra \
	-fno-strict-aliasing -Wno-strict-aliasing \
	-Wno-missing-braces -Wno-missing-field-initializers \
	-Wno-address-of-packed-member

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst %.c,%.o,${SRCS})

# Everything but main(), so the unit tests can link the real implementation.
LIB_OBJS = $(filter-out src/ndppd.o,${OBJS})

all: ndppd ndppd.8.gz ndppd.conf.5.gz

install: all
	mkdir -p ${SBINDIR} ${MANDIR} ${MANDIR}/man8 ${MANDIR}/man5
	cp ndppd ${SBINDIR}
	chmod +x ${SBINDIR}/ndppd
	cp ndppd.8.gz ${MANDIR}/man8
	cp ndppd.conf.5.gz ${MANDIR}/man5

%.gz: %.adoc
	${ASCIIDOCTOR} -b manpage $< -o - | ${GZIP} > $@

ndppd: ${OBJS}
	${CC} -o ndppd ${LDFLAGS} ${OBJS} ${LIBS}

%.o: %.c
	${CC} -c ${CPPFLAGS} $(CFLAGS) -o $@ $<

# The 1.0 tree amalgamated its headers, so every .c in src/ includes
# src/ndppd.h and nothing else -- which means every object depends on it.
# Without this rule, editing that header leaves all twelve objects stale and
# `make ndppd` reports the binary up to date while the build quietly keeps
# the old code.  That is how a version bump can be committed, built and
# still announce the previous version on startup.
#
# A wildcard rather than a literal filename: if the header is ever split up
# again, the new pieces are picked up instead of silently reintroducing this.
# Not generated depfiles (-MMD), because ndppd aims to build with nothing
# but a compiler on platforms as old and odd as #67 and #73, and a single
# amalgamated header needs nothing cleverer than this.
HDRS = $(wildcard src/*.h)

${OBJS}: ${HDRS}

# --- tests ----------------------------------------------------------------
#
# Two layers, both emitting TAP 13.  See test/README.md.
#
#   check-unit         pure logic; no privileges, no network, no waiting
#   check-integration  a real daemon on real interfaces, in namespaces
#
# The unit binary links the production objects for addr, alloc, conf, log,
# proxy, rule and session, and substitutes test/unit/fake.c for iface.c,
# rt.c and io.c -- the two places ndppd needs a kernel.  That keeps the code
# under test the shipped code while making every emitted NS and NA
# inspectable and making nd_current_time an ordinary variable.
#
# NDPPD_TEST_SRCDIR lets a test find ndppd.conf-dist regardless of the
# directory it is run from.

TEST_UNIT_SRCS = $(wildcard test/unit/*.c)
TEST_UNIT_OBJS = $(patsubst %.c,%.o,${TEST_UNIT_SRCS})
TEST_UNIT_BIN  = test/unit/ndppd-unit-tests

TEST_LIB_OBJS = src/addr.o src/alloc.o src/conf.o src/log.o \
		src/proxy.o src/rule.o src/session.o

test/unit/%.o: test/unit/%.c
	${CC} -c ${CPPFLAGS} $(CFLAGS) -I src -I test/unit \
	    -DNDPPD_TEST_SRCDIR='"$(CURDIR)"' -o $@ $<

# Same reasoning as ${OBJS} above; the unit sources include src/ndppd.h as
# well as their own tap.h and fake.h.
TEST_UNIT_HDRS = $(wildcard test/unit/*.h)

${TEST_UNIT_OBJS}: ${HDRS} ${TEST_UNIT_HDRS}

# TEST_LDFLAGS rather than LDFLAGS: the release link uses -s, and a
# stripped test binary makes a sanitizer report unreadable.  CI overrides
# this for the ASan/UBSan job.
TEST_LDFLAGS ?=

${TEST_UNIT_BIN}: ${TEST_UNIT_OBJS} ${TEST_LIB_OBJS}
	${CC} -o $@ ${TEST_LDFLAGS} ${TEST_UNIT_OBJS} ${TEST_LIB_OBJS} ${LIBS}

check-unit: ${TEST_UNIT_BIN}
	./${TEST_UNIT_BIN}

check-integration: ndppd
	./test/integration/run.sh

check: check-unit check-integration

test: check

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.8.gz ${OBJS} \
	      ${TEST_UNIT_OBJS} ${TEST_UNIT_BIN}

.PHONY: all install clean check check-unit check-integration test
