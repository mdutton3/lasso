PHP_PACKAGE=lasso

SWIG_OUTPUTS=$(PHP_PACKAGE)_wrap.c php_$(PHP_PACKAGE).h $(PHP_PACKAGE).php

php_extension_LTLIBRARIES = lasso.la
lasso_la_CFLAGS = $(LASSO_CFLAGS) \
			 -I$(top_srcdir) \
			 $(PHP_INCLUDES)
lasso_la_LDFLAGS = -export-dynamic \
		  	  -prefer-pic \
		 	  -module \
		 	  -avoid-version
lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la \
		 	 $(LASSO_LIBS) \
		 	 $(PHP_LDFLAGS)
lasso_la_SOURCES=$(PHP_PACKAGE)_wrap.c

php_extensiondir=${prefix}@PHP_UNPREFIXED_EXTENSION_DIR@

$(PHP_PACKAGE)_wrap.c php_$(PHP_PACKAGE).h $(PHP_PACKAGE).php: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -php4 -noproxy \
		-module $(PHP_PACKAGE) \
		-o $(PHP_PACKAGE)_wrap.c \
		-dlname $(PHP_PACKAGE) \
		$<

$(DEPDIR)/lasso_la-$(PHP_PACKAGE)_wrap.Plo:
	echo "#dummy" > $(DEPDIR)/lasso_la-$(PHP_PACKAGE)_wrap.Plo

test-php: lasso.la $(PHP_PACKAGE).php
	$(PHP) -d extension_dir=.libs $(srcdir)/$(PHP_PACKAGE).php


MAINTAINERCLEANFILES=$(SWIG_OUTPUTS)
EXTRA_DIST=$(SWIG_OUTPUTS)
