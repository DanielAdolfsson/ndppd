all:
	cd src && make all && cp ndppd ..

clean:
	rm -f ndppd
	cd src && make clean

 
 
