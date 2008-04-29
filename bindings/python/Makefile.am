SUBDIRS = tests

if PYTHON_ENABLED
INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

pythondir= $(PY_SITE_PACKAGES)
python_DATA = lasso.py
python_LTLIBRARIES = _lasso.la

_lasso_la_SOURCES = _lasso.c
_lasso_la_CFLAGS = $(LASSO_CORE_CFLAGS) -DSWIG_COBJECT_TYPES $(PY_CFLAGS)
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

_lasso.c:
	$(PYTHON) $(top_srcdir)/bindings/bindings.py -l python --src-dir=$(top_srcdir)/lasso/

endif
