FROM		ubuntu:14.10
MAINTAINER	Guillaume J. Charmes <guillaume@charmes.net>

RUN		apt-get update && apt-get install -y build-essential
ENTRYPOINT	["/start.sh"]

ADD		Makefile  ndppd.1  ndppd.conf.5 /ndppd/
ADD		src /ndppd/src/
RUN		cd /ndppd && make all && make install

ADD		start.sh /
