#!/usr/local/bin/bash

DEV=$1
FAMILY=$2
REMOTE_IP=$4

IPV6PREFIX="2a02:2928:3:"

if [ X${DEV} == "X" ]; then
	exit 1
fi

if [ X${REMOTE_IP} == "X" ]; then
	exit 1
fi

if [ ${FAMILY} == "inet" ]; then
	OCTET1=`echo $REMOTE_IP | cut -d. -f3`
	OCTET2=`echo $REMOTE_IP | cut -d. -f4`
	HEXOCTETS=`printf "%x" $(($OCTET1 << 8 | $OCTET2))`
	REMOTE_IPV6="${IPV6PREFIX}${HEXOCTETS}"

	/sbin/ifconfig $DEV inet6 ${REMOTE_IPV6}::1 prefixlen 64 alias
	echo "global $DEV ${REMOTE_IPV6}::" | nc localhost 5007

	exit 0
fi

if [ ${FAMILY} == "inet6" ]; then
	echo "enable $DEV" | nc localhost 5007
	exit 0
fi

exit 1
