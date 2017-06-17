#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
./hijack_session 8000 00 00 00 aa 00 02
