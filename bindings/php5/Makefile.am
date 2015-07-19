CLEANFILES = lasso.php php_lasso.h _lasso.c
DISTCLEANFILES = __init__.pyc lang.pyc php_code.pyc wrapper_header.pyc wrapper_top.pyc wrapper_source.pyc
SUBDIRS = examples tests

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

php_extensiondir = ${prefix}@PHP5_UNPREFIXED_EXTENSION_DIR@
php_extension_LTLIBRARIES = lasso.la

php_includedir = @PHP5_INCLUDE_DIR@
nodist_php_include_DATA = lasso.php

php_configdir=@PHP5_CONFIG_DIR@
php_config_DATA = lasso.ini

lasso_la_CFLAGS = -fno-strict-aliasing $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(PHP5_INCLUDES) $(AM_CFLAGS)
lasso_la_CFLAGS += -Wno-unused-parameter -Wno-sign-compare # problem in zend.h
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP5_LDFLAGS)
nodist_lasso_la_SOURCES = _lasso.c

BUILT_SOURCES = _lasso.c

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif


lasso.php _lasso.c: lang.py wrapper_source.py wrapper_header.py wrapper_source_top.c php_code.py ../overrides.xml
	$(AM_V_GEN) $(PYTHON) $(top_srcdir)/bindings/bindings.py -l php5 --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

doc:
	phpdoc -o HTML:frames:earthli -f lasso.php -t docs


.PHONY: doc

EXTRA_DIST = lasso.ini lang.py php_code.py wrapper_header.py wrapper_source.py __init__.py wrapper_source_top.c
