SUBDIRS = environs tests xml

PHP_PACKAGE=lasso

liblasso_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/lasso/.libs $(PHP_LDFLAGS)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PHP_INCLUDES) \
	$(NULL)


mylibs = $(top_builddir)/lasso/liblasso.la

LASSOSOURCES = lasso.c lasso.h php_lasso.h

lib_LTLIBRARIES = liblasso.la \
				  $(NULL)
				  
liblasso_la_SOURCES = $(LASSOSOURCES)
liblasso_la_LIBADD = $(mylibs) \
				  ./environs/libenvirons.a \
				  ./xml/libxml.a \
				  $(PHP_LIBS) \
				  $(NULL)
