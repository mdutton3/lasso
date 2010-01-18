#!/bin/sh

php5 -n -d extension_dir=../.libs -d extension=lasso.so ${SRCDIR}binding_tests.php
