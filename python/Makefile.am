INCLUDES = -I$(top_srcdir)

pythondir= $(PY_SITE_PACKAGES)
python_DATA = lasso.py
python_LTLIBRARIES = _lasso.la

_lasso_la_SOURCES = lasso_wrap.c
_lasso_la_CFLAGS = $(LASSO_CFLAGS) -DSWIG_COBJECT_TYPES $(PY_CFLAGS)
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
lasso_wrap.c lasso.py: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -python -module lasso -o lasso_wrap.c $<

SWIG_OUTPUTS = lasso_wrap.c lasso.py

# In distribution, swig generated files are present.
EXTRA_DIST = $(SWIG_OUTPUTS)

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)
