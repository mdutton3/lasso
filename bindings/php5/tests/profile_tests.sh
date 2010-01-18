#!/bin/sh

php5 -n -d extension_dir=../.libs -d extension=lasso.so ${SRCDIR}profile_tests.php
