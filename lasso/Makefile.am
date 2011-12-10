SUBDIRS = xml id-ff saml-2.0
if WSF_ENABLED
SUBDIRS +=  id-wsf-2.0 id-wsf
endif

liblassoincludedir = $(includedir)/lasso

INCLUDES = -I$(top_builddir) -I$(top_srcdir) $(LASSO_CORE_CFLAGS)

## Added to activate libtool 1.5.6 windows resources partial support
LTRCCOMPILE = $(LIBTOOL) --tag=RC --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) |\
         sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

## Added to activate libtool 1.5.6 windows resources partial support
lasso.rc.lo: $(top_srcdir)/win32/lasso.rc
	$(LTRCCOMPILE) -i $< -o $@

lib_LTLIBRARIES = liblasso.la

liblassoinclude_HEADERS = export.h lasso.h lasso_config.h errors.h \
			  registry.h ctypes.h key.h
nodist_liblassoinclude_HEADERS = debug.h utils.h registry-private.h logging.h backward_comp.h keyprivate.h
BUILT_SOURCES = types.c errors.c symbols.sym

liblasso_la_SOURCES = lasso.c errors.c registry.c utils.c logging.c key.c

if WSF_ENABLED
SYMBOLS_ARGS = -wsf
endif

types.c: $(srcdir)/*.h $(srcdir)/*/*.h $(srcdir)/*/*/*.h
	$(PYTHON) $(srcdir)/extract_types.py $(srcdir) $(SYMBOLS_ARGS)

symbols.sym: $(srcdir)/*.h $(srcdir)/*/*.h $(srcdir)/*/*/*.h
	$(PYTHON) $(srcdir)/extract_symbols.py $(srcdir) $(SYMBOLS_ARGS) > symbols.sym

MAINTAINERCLEANFILES = \
	Makefile.in \
	lasso_config.h.in

clean-local:
	-rm -f types.c symbols.sym errors.c

EXTRA_DIST = $(nodist_liblassoinclude_HEADERS) extract_types.py extract_symbols.py build_strerror.py \
	     errors.c.in extract_sections.py errors.c

if WSF_ENABLED
WSF_LIB_FILE = $(top_builddir)/lasso/id-wsf/liblasso-id-wsf.la

WSF2_LIB_FILES = $(top_builddir)/lasso/id-wsf-2.0/liblasso-id-wsf2.la \
	$(top_builddir)/lasso/xml/id-wsf-2.0/liblasso-xml-id-wsf-2.la \
	$(top_builddir)/lasso/xml/ws/liblasso-xml-ws.la
endif

if MINGW
liblasso_la_LIBADD = \
	$(top_builddir)/lasso/xml/liblasso-xml.la \
	$(top_builddir)/lasso/xml/saml-2.0/liblasso-xml-saml2.la \
	$(top_builddir)/lasso/xml/soap-1.1/liblasso-xml-soap11.la \
	$(top_builddir)/lasso/xml/dsig/liblasso-xml-dsig.la \
	$(top_builddir)/lasso/id-ff/liblasso-id-ff.la \
	$(top_builddir)/lasso/saml-2.0/liblasso-saml-20.la \
	$(WSF_LIB_FILE) \
	$(WSF2_LIB_FILES) \
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
	$(top_builddir)/lasso/xml/saml-2.0/liblasso-xml-saml2.la \
	$(top_builddir)/lasso/xml/soap-1.1/liblasso-xml-soap11.la \
	$(top_builddir)/lasso/xml/dsig/liblasso-xml-dsig.la \
	$(top_builddir)/lasso/id-ff/liblasso-id-ff.la \
	$(top_builddir)/lasso/saml-2.0/liblasso-saml-20.la \
	$(WSF_LIB_FILE) \
	$(WSF2_LIB_FILES) \
	$(LASSO_LIBS)
# Just make damn sure the ABI stays the same between
# upgrades.
# Obviously if you don't, fixing the situation up again can be painful. 
liblasso_la_LDFLAGS = -no-undefined -version-info @LASSO_VERSION_INFO@  \
	-export-symbols symbols.sym
endif

$(srcdir)/errors.c: $(srcdir)/errors.h $(srcdir)/build_strerror.py
	python $(srcdir)/build_strerror.py $(srcdir) >.errors.c.new
	if ! cmp -s $(srcdir)/errors.c .errors.c.new; then \
	mv -f .errors.c.new $@; else \
	rm .errors.c.new; fi
