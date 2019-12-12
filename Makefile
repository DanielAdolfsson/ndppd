ifdef DEBUG
CCFLAGS ?= -g -DDEBUG
else
CCFLAGS ?= -Os
LDFLAGS ?= -s -w
endif

PREFIX      ?= /usr/local
CCC         ?= gcc
GZIP        ?= /bin/gzip
MANDIR      ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR     ?= ${DESTDIR}${PREFIX}/sbin
ASCIIDOCTOR ?= /usr/bin/asciidoctor

OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))

all: ndppd ndppd.8.gz ndppd.conf.5.gz

install: all
	mkdir -p ${SBINDIR} ${MANDIR} ${MANDIR}/man1 ${MANDIR}/man5
	cp ndppd ${SBINDIR}
	chmod +x ${SBINDIR}/ndppd
	cp ndppd.8.gz ${MANDIR}/man1
	cp ndppd.conf.5.gz ${MANDIR}/man5

%.gz: %.adoc
	${ASCIIDOCTOR} -b manpage $< -o - | ${GZIP} > $@

ndppd: ${OBJS}
	${CC} -o ndppd ${LDFLAGS} ${OBJS} ${LIBS}

%.o: %.c
	${CC} -c ${CPPFLAGS} $(CCFLAGS) -o $@ $<

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.8.gz ${OBJS}
