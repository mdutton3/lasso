NULL = 	
SUBDIRS = xml protocols profiles

liblassoincludedir = $(includedir)/lasso

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(GLIB_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(XMLSEC1_CFLAGS) \
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
	$(top_builddir)/lasso/profiles/liblasso-profiles.la \
	$(GLIB_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(XMLSEC1_LIBS) \
	$(NULL)

liblasso_la_LDFLAGS = \
	-version-info @LASSO_VERSION_INFO@ \
	$(NULL)
