PREFIX   =
MANDIR   = ${PREFIX}/usr/share/man
BINDIR   = ${PREFIX}/usr/local/bin

install: all
	mkdir -p ${BINDIR} ${MANDIR}
	cp ndppd ${BINDIR}
	chmod +x ${BINDIR}/ndppd
	cp ndppd.1.gz ${MANDIR}/man1
	cp ndppd.conf.5.gz ${MANDIR}/man5

all: ndppd ndppd.1.gz ndppd.conf.5.gz

ndppd:
	cd src && make all && cp ndppd ..

clean:
	rm -f ndppd ndppd.conf.5.gz ndppd.1.gz
	cd src && make clean

ndppd.1.gz:
	gzip < ndppd.1 > ndppd.1.gz

ndppd.conf.5.gz:
	gzip < ndppd.conf.5 > ndppd.conf.5.gz
