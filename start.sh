#!/bin/sh

if [ -z $1 ]; then
    echo "Please specify the ipv6 to proxy"
    exit 1
fi

cat <<EOF > /tmp/ndppd.conf
route-ttl 5000
proxy eth0 {
  rule $1 {
    auto
  }
}
EOF
ndppd -c /tmp/ndppd.conf
