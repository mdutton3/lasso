#!/bin/bash

echo Check makefiles for missing .c or .h files

cd `dirname $0`/..

for i in `git ls-files *.c *.h`; do
	pushd `dirname $i` >/dev/null
	f=`basename $i`
	if ! grep -q $f Makefile.am; then
		echo $i
	fi
	popd >/dev/null
done
