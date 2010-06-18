#!/bin/bash
DATE=`date +%FT%TZ`
if [ $1 == 'python' ]; then
	NAME=`basename $2`
else
	NAME=$1
fi
env G_DEBUG=gc-friendly MALLOC_CHECK_=2 G_SLICE=always-malloc valgrind --show-reachable=yes --suppressions=../valgrind/lasso.supp --suppressions=../valgrind/glib.supp --suppressions=../valgrind/openssl.supp --suppressions=/usr/lib/valgrind/python.supp --leak-check=full --log-file="${NAME}_${DATE}_pid-$$.log" --track-origins=yes "$@"


