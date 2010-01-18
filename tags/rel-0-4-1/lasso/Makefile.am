SUBDIRS = xml protocols environs

liblassoincludedir = $(includedir)/lasso

INCLUDES = \
	-I$(top_srcdir) \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS)

## Added to activate libtool 1.5.6 windows resources partial support
LTRCCOMPILE = $(LIBTOOL) --tag=RC --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) |\
         sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

## Added to activate libtool 1.5.6 windows resources partial support
lasso.rc.lo: $(top_srcdir)/win32/lasso.rc
	$(LTRCCOMPILE) -i $< -o $@


lib_LTLIBRARIES = liblasso.la

liblassoinclude_HEADERS = export.h lasso.h lasso_config.h

liblasso_la_SOURCES = lasso.c

if MINGW
liblasso_la_LIBADD = \
	$(top_builddir)/lasso/xml/liblasso-xml.la \
	$(top_builddir)/lasso/protocols/liblasso-protocols.la \
	$(top_builddir)/lasso/environs/liblasso-environs.la \
	$(LASSO_LIBS) \
	lasso.rc.lo
# Just make damn sure the ABI stays the same between
# upgrades.
# Obviously if you don't, fixing the situation up again can be painful. 
liblasso_la_LDFLAGS = -no-undefined -version-info @LASSO_VERSION_INFO@ \
                      -Wl,--add-stdcall-alias 
else
liblasso_la_LIBADD = \
	$(top_builddir)/lasso/xml/liblasso-xml.la \
	$(top_builddir)/lasso/protocols/liblasso-protocols.la \
	$(top_builddir)/lasso/environs/liblasso-environs.la \
	$(LASSO_LIBS)
# Just make damn sure the ABI stays the same between
# upgrades.
# Obviously if you don't, fixing the situation up again can be painful. 
liblasso_la_LDFLAGS = -no-undefined -version-info @LASSO_VERSION_INFO@
endif


