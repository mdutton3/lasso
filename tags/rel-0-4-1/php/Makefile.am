SWIG_OUTPUTS = lasso_wrap.c php_lasso.h lasso.php

php_extension_LTLIBRARIES = lasso.la
lasso_la_CFLAGS = $(LASSO_CFLAGS) -I$(top_srcdir) $(PHP_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP_LDFLAGS)
lasso_la_SOURCES = lasso_wrap.c

php_extensiondir = ${prefix}@PHP_UNPREFIXED_EXTENSION_DIR@

lasso_wrap.c php_lasso.h lasso.php: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -php4 -module lasso -o lasso_wrap.c -dlname lasso $<

test-php: lasso.la lasso.php
	$(PHP) -d extension_dir=.libs $(srcdir)/lasso.php

MAINTAINERCLEANFILES=$(SWIG_OUTPUTS)
EXTRA_DIST=$(SWIG_OUTPUTS)
SUBDIRS=examples
