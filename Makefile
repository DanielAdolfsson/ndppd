ifdef DEBUG
MFLAGS   = DEBUG=${DEBUG}
else
MFLAGS   =
endif

MANDIR  = ${DESTDIR}/usr/share/man
SBINDIR = ${DESTDIR}/usr/sbin

all: ndppd ndppd.1.gz ndppd.conf.5.gz

install: all
	mkdir -p ${SBINDIR} ${MANDIR} ${MANDIR}/man1 ${MANDIR}/man5
	cp ndppd ${SBINDIR}
	chmod +x ${SBINDIR}/ndppd
	cp ndppd.1.gz ${MANDIR}/man1
	cp ndppd.conf.5.gz ${MANDIR}/man5

ndppd:
	cd src && make ${MFLAGS} all && cp ndppd ..

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.1.gz
	cd src && make clean

ndppd.1.gz:
	gzip < ndppd.1 > ndppd.1.gz

ndppd.conf.5.gz:
	gzip < ndppd.conf.5 > ndppd.conf.5.gz
