ifdef DEBUG
CFLAGS  ?= -g -DDEBUG
else
CFLAGS  ?= -Os
LDFLAGS ?= -s -w
endif

PREFIX      ?= /usr/local
CC          ?= gcc
GZIP        ?= /bin/gzip
MANDIR      ?= ${DESTDIR}${PREFIX}/share/man
SBINDIR     ?= ${DESTDIR}${PREFIX}/sbin
ASCIIDOCTOR ?= /usr/bin/asciidoctor

CFLAGS := ${CFLAGS} -Werror -Wall -Wextra -Wno-missing-braces -Wno-missing-field-initializers

OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))

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

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.8.gz ${OBJS}
