SUBDIRS = examples

if PHP5_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

php_extensiondir = ${prefix}@PHP5_UNPREFIXED_EXTENSION_DIR@
php_extension_LTLIBRARIES = lasso.la

php_includedir = @PHP5_INCLUDE_DIR@
nodist_php_include_DATA = lasso.php

php_configdir=@PHP5_CONFIG_DIR@
php_config_DATA = lasso.ini

lasso_la_CFLAGS = -fno-strict-aliasing $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(PHP5_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP5_LDFLAGS)
nodist_lasso_la_SOURCES = _lasso.c

BUILT_SOURCES = _lasso.c

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

lasso.php _lasso.c: ../lang_php5.py ../lang_php5_helpers/php_code.py ../lang_php5_helpers/wrapper_source.py ../lang_php5_helpers/wrapper_source_top.c ../overrides.xml
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l php5 --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

doc:
	phpdoc -o HTML:frames:earthli -f lasso.php -t docs

clean-local:
	-rm -f lasso.php php_lasso.h _lasso.c

.PHONY: doc

endif

EXTRA_DIST = lasso.ini
