PHP_PACKAGE=lasso

SWIG_OUTPUTS=$(PHP_PACKAGE)_wrap.c php_$(PHP_PACKAGE).h $(PHP_PACKAGE).php

lib_LTLIBRARIES = php_lasso.la
php_lasso_la_CFLAGS = $(LASSO_CFLAGS) \
			 -I$(top_srcdir) \
			 $(PHP_INCLUDES)
php_lasso_la_LDFLAGS = -export-dynamic \
		  	  -prefer-pic \
		 	  -module \
		 	  -avoid-version
php_lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la \
		 	 $(LASSO_LIBS) \
		 	 $(PHP_LDFLAGS)
php_lasso_la_SOURCES=$(PHP_PACKAGE)_wrap.c

libdir=${prefix}@PHP_UNPREFIXED_EXTENSION_DIR@

$(PHP_PACKAGE)_wrap.c php_$(PHP_PACKAGE).h: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -php4 -noproxy -module $(PHP_PACKAGE) -o $(PHP_PACKAGE)_wrap.c $<

$(DEPDIR)/php_lasso_la-$(PHP_PACKAGE)_wrap.Plo:
	echo "#dummy" > .deps/libjlasso_la-lasso_wrap.Plo 

test-php: php_lasso.la
	$(PHP) -d extension_dir=.libs $(PHP_PACKAGE).php


MAINTAINERCLEANFILES=$(SWIG_OUTPUTS)
EXTRA_DIST=$(SWIG_OUTPUTS)
