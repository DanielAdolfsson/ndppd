ifdef DEBUG
CXXFLAGS ?= -g -DDEBUG
else
CXXFLAGS ?= -O3
endif

PREFIX  ?= /usr/local
CXX     ?= g++
LDFLAGS ?= -lconfuse
OBJ     ?= src/log.o src/ndppd.o src/iface.o src/proxy.o src/address.o \
           src/rule.o src/session.o src/conf.o
GZIP    ?= /bin/gzip
MANDIR  ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR ?= ${DESTDIR}${PREFIX}/sbin

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

ndppd: ${OBJ}
	${CXX} -o ndppd ${LDFLAGS} ${OBJ}

.cc.o:
	${CXX} -c $(CXXFLAGS) -o $@ $<

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.1.gz ${OBJ}
