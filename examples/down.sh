#!/usr/local/bin/bash

DEV=$1

nc "disable $DEV" | nc localhost 5007

exit 0
