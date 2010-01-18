SWIG_OUTPUTS = lasso_wrap.c php_lasso.h lasso.php

php_extension_LTLIBRARIES = lasso.la
lasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -I$(top_builddir) -I$(top_srcdir) $(PHP4_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS) $(PHP4_LDFLAGS)
lasso_la_SOURCES = lasso_wrap.c

php_extensiondir = ${prefix}@PHP4_UNPREFIXED_EXTENSION_DIR@

SWIG_I_FILES=$(shell find $(top_srcdir)/swig/ -name '*.[ih]')
lasso_wrap.c php_lasso.h lasso.php: $(SWIG_I_FILES)
	$(SWIG) -I$(top_builddir)/swig -v -php4 -module lasso -o lasso_wrap.c $(top_srcdir)/swig/Lasso.i
	cp lasso_wrap.c lasso_wrap.c.bak
	test x"$(SWIG)" = xecho || \
		$(PYTHON) $(srcdir)/patch_swig_output.py $(SWIG_VERSION) < lasso_wrap.c.bak > lasso_wrap.c

test-php: lasso.la lasso.php
	$(PHP4) -d extension_dir=.libs $(srcdir)/lasso.php

MAINTAINERCLEANFILES = Makefile.in $(SWIG_OUTPUTS)
EXTRA_DIST = patch_swig_output.py $(SWIG_OUTPUTS)

clean-local:
	rm -f lasso_wrap.c.bak

