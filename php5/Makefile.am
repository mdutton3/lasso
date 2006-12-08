SWIG_OUTPUTS = lasso_wrap.c php_lasso.h lasso.php

php_extension_LTLIBRARIES = lasso.la
lasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -I$(top_srcdir) -I$(top_builddir) $(PHP5_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP5_LDFLAGS)
lasso_la_SOURCES = lasso_wrap.c

php_extensiondir = ${prefix}@PHP5_UNPREFIXED_EXTENSION_DIR@

SWIG_I_FILES=$(shell find $(top_srcdir)/swig/ -name '*.[ih]')
lasso_wrap.c php_lasso.h lasso.php: $(SWIG_I_FILES)
	$(SWIG) -v -php5 -module lasso -o lasso_wrap.c $(top_srcdir)/swig/Lasso.i

test-php: lasso.la lasso.php
	$(PHP5) -d extension_dir=.libs $(srcdir)/lasso.php

MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)
EXTRA_DIST = $(SWIG_OUTPUTS)

