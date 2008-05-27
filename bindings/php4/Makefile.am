MAINTAINERCLEANFILES = Makefile.in
SUBDIRS = 

if PHP4_ENABLED
INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

php_extension_LTLIBRARIES = lasso.la
php_extensiondir = ${prefix}@PHP4_UNPREFIXED_EXTENSION_DIR@

nodist_php_extension_DATA = lasso.php

lasso_la_CFLAGS = -fno-strict-aliasing $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(PHP4_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP4_LDFLAGS)
nodist_lasso_la_SOURCES = _lasso.c

BUILT_SOURCES = _lasso.c

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

lasso.php _lasso.c: lang.py ../bindings.py
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l php4 --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

doc:
	phpdoc -o HTML:frames:earthli -f lasso.php -t docs

clean-local:
	-rm -f lasso.php php_lasso.h _lasso.c
	-rm -f *.pyc

.PHONY: doc

endif
