ifdef DEBUG
CFLAGS   = -g -DDEBUG
else
CFLAGS   = -O3
endif

CC       = g++
LDFLAGS  = -lconfuse
OBJ      = log.o ndppd.o iface.o proxy.o address.o rule.o session.o conf.o


all: ndppd

ndppd: ${OBJ}
	${CC} -o ndppd ${LDFLAGS} ${OBJ}

.cc.o:
	${CC} -c $(CFLAGS) $<

clean:
	rm -f ndppd ${OBJ}
 
 
