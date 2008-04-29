if PHP5_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

php_extension_LTLIBRARIES = lasso.la
php_extensiondir = ${prefix}@PHP5_UNPREFIXED_EXTENSION_DIR@

lasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(PHP4_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP4_LDFLAGS)
lasso_la_SOURCES = _lasso.c

_lasso.c:
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l php5 --src-dir=$(top_srcdir)/lasso/

doc:
	phpdoc -o HTML:frames:earthli -f lasso.php -t docs

endif
