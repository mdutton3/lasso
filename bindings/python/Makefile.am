MAINTAINERCLEANFILES = Makefile.in
CLEANFILES = _lasso.c lasso.py
DISTCLEANFILES = __init__.pyc lasso.pyc lang.pyc
SUBDIRS = tests

if PYTHON_ENABLED
INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(SASL_CFLAGS)

pythondir= $(PY_SITE_PACKAGES)
nodist_python_DATA = lasso.py
python_LTLIBRARIES = _lasso.la

nodist__lasso_la_SOURCES = _lasso.c
_lasso_la_CFLAGS = -fno-strict-aliasing $(LASSO_CORE_CFLAGS) $(PY_CFLAGS) $(AM_CFLAGS)
_lasso_la_LIBADD = $(top_builddir)/lasso/liblasso.la $(LASSO_LIBS)
if DARWIN
_lasso_la_LDFLAGS = -no-undefined -module -avoid-version -Wl,-F. -Wl,-F. -bundle -framework Python 
else
if MINGW
_lasso_la_LDFLAGS = -no-undefined -module -avoid-version -Wl,--add-stdcall-alias
else
_lasso_la_LDFLAGS = -no-undefined -module -avoid-version
endif
endif

BUILT_SOURCES = _lasso.c

_lasso.c lasso.py: $(top_srcdir)/lasso/*.h $(top_srcdir)/lasso/*.c $(top_srcdir)/lasso/*/*.h $(top_srcdir)/lasso/*/*.c $(top_srcdir)/lasso/*/*/*.h $(top_srcdir)/lasso/*/*/*.c

EXTRA_DIST=lang.py wrapper_bottom.c wrapper_top.c __init__.py examples

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

lasso.py _lasso.c: lang.py wrapper_top.c wrapper_bottom.c ../bindings.py
	$(AM_V_GEN) $(PYTHON) $(top_srcdir)/bindings/bindings.py -l python --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)


endif
