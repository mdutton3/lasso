#!/bin/sh

${PHP5:?PHP5 variable is not defined} -n -d extension_dir=../.libs -d extension=lasso.so ${SRCDIR}profile_tests.php
