SUBDIRS = environs tests xml

PHP_PACKAGE=lasso

lasso_la_LDFLAGS = -export-dynamic -prefer-pic -module -avoid-version -L$(top_builddir)/lasso/.libs $(PHP_LDFLAGS)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PHP_INCLUDES)


mylibs = $(top_builddir)/lasso/liblasso.la

LASSOSOURCES = \
			   lasso.c \
			   lasso.h \
			   php_lasso.h

lib_LTLIBRARIES = lasso.la
		
libdir=${prefix}@PHP_UNPREFIXED_EXTENSION_DIR@
				  
lasso_la_SOURCES = $(LASSOSOURCES)
lasso_la_LIBADD = $(mylibs) $(LASSO_LIBS) ./environs/libenvirons.a ./xml/libxml.a

