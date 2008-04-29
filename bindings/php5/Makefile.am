if PHP5_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

php_extension_LTLIBRARIES = lasso.la
php_extensiondir = ${prefix}@PHP5_UNPREFIXED_EXTENSION_DIR@

nodist_php_extension_DATA = lasso.php

lasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(PHP5_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP5_LDFLAGS)
nodist_lasso_la_SOURCES = _lasso.c

BUILT_SOURCES = _lasso.c

_lasso.c:
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l php5 --src-dir=$(top_srcdir)/lasso/

doc:
	phpdoc -o HTML:frames:earthli -f lasso.php -t docs

clean-local:
	-rm lasso.php php_lasos.h _lasso.c

.PHONY: doc

endif
