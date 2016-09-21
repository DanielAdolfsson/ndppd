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

LIBS     =

OBJS     = src/logger.o src/ndppd.o src/iface.o src/proxy.o src/address.o \
           src/rule.o src/session.o src/conf.o src/route.o

all: ndppd ndppd.1.gz ndppd.conf.5.gz nd-proxy

install: all
	mkdir -p ${SBINDIR} ${MANDIR} ${MANDIR}/man1 ${MANDIR}/man5
	cp ndppd ${SBINDIR}
	chmod +x ${SBINDIR}/ndppd
	cp ndppd.1.gz ${MANDIR}/man1
	cp ndppd.conf.5.gz ${MANDIR}/man5
	cp nd-proxy ${SBINDIR}

ndppd.1.gz:
	${GZIP} < ndppd.1 > ndppd.1.gz

ndppd.conf.5.gz:
	${GZIP} < ndppd.conf.5 > ndppd.conf.5.gz

ndppd: ${OBJS}
	${CXX} -o ndppd ${LDFLAGS} ${LIBS} ${OBJS}

nd-proxy: nd-proxy.c
	${CXX} -o nd-proxy -Wall -Werror ${LDFLAGS} `pkg-config --cflags glib-2.0` nd-proxy.c `pkg-config --libs glib-2.0`

.cc.o:
	${CXX} -c ${CPPFLAGS} $(CXXFLAGS) -o $@ $<

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.1.gz ${OBJS} nd-proxy
