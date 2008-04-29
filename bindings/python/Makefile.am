SUBDIRS = tests

if PYTHON_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

pythondir= $(PY_SITE_PACKAGES)
nodist_python_DATA = lasso.py
python_LTLIBRARIES = _lasso.la

nodist__lasso_la_SOURCES = _lasso.c
_lasso_la_CFLAGS = -fno-strict-aliasing $(LASSO_CORE_CFLAGS) $(PY_CFLAGS)
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

if WSF_ENABLED
EXTRA_ARGS = --enable-id-wsf
endif

lasso.py _lasso.c:
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l python --src-dir=$(top_srcdir)/lasso/ $(EXTRA_ARGS)

clean-local:
	-rm -f lasso.py lasso.pyc _lasso.c

endif
