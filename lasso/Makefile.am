NULL = 	
SUBDIRS = xml protocols environs

liblassoincludedir = $(includedir)/lasso

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	$(NULL)

lib_LTLIBRARIES = \
	liblasso.la \
	$(NULL)

liblassoinclude_HEADERS = \
	export.h	\
	lasso.h	\
	version.h \
	$(NULL)

liblasso_la_SOURCES = \
	lasso.c \
	$(NULL)

liblasso_la_LIBADD = \
	$(top_builddir)/lasso/xml/liblasso-xml.la \
	$(top_builddir)/lasso/protocols/liblasso-protocols.la \
	$(top_builddir)/lasso/environs/liblasso-environs.la \
	$(LASSO_LIBS) \
	$(NULL)

liblasso_la_LDFLAGS = \
	-version-info @LASSO_VERSION_INFO@ \
	$(NULL)
