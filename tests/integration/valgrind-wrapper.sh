#!/bin/bash
DATE=`date +%FT%TZ`
if [ $1 == 'python' ]; then
	NAME=`basename $2`
else
	NAME=$1
fi
env MALLOC_CHECK_=2 G_SLICE=always-malloc PYTHONPATH=/home/bdauvergne/wd/lasso/git/bindings/python:/home/bdauvergne/wd/lasso/git/bindings/python/.libs LD_LIBRARY_PATH=/home/bdauvergne/wd/lasso/git/lasso/.libs valgrind --show-reachable=yes --suppressions=../valgrind/lasso.supp --suppressions=../valgrind/glib.supp --suppressions=../valgrind/openssl.supp --suppressions=/usr/lib/valgrind/python.supp --leak-check=full --log-file="${NAME}_${DATE}_pid-$$.log" --track-origins=yes "$@"


