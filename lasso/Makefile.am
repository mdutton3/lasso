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

## Added to activate libtool 1.5.6 windows resources partial support
LTRCCOMPILE = $(LIBTOOL) --tag=RC --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) |\
         sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

## Added to activate libtool 1.5.6 windows resources partial support
lasso.rc.lo: ../win32/lasso.rc
	$(LTRCCOMPILE) -i $< -o $@


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

if MINGW
liblasso_la_LIBADD = \
	$(top_builddir)/lasso/xml/liblasso-xml.la \
	$(top_builddir)/lasso/protocols/liblasso-protocols.la \
	$(top_builddir)/lasso/environs/liblasso-environs.la \
	$(LASSO_LIBS) \
	lasso.rc.lo \
	$(NULL)
else
liblasso_la_LIBADD = \
	$(top_builddir)/lasso/xml/liblasso-xml.la \
	$(top_builddir)/lasso/protocols/liblasso-protocols.la \
	$(top_builddir)/lasso/environs/liblasso-environs.la \
	$(LASSO_LIBS) \
	$(NULL)
endif

liblasso_la_LDFLAGS = \
	-no-undefined -version-info @LASSO_VERSION_INFO@ \
	$(NULL)
