INCLUDES = -I$(top_srcdir) \
	-I$(top_builddir) \
	$(SASL_CFLAGS)

pythondir= $(PY_SITE_PACKAGES)
python_DATA = lasso.py
python_LTLIBRARIES = _lasso.la

_lasso_la_SOURCES = lasso_wrap.c
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
SWIG_I_FILES=$(shell find $(top_srcdir)/swig/ -name '*.[ih]')
lasso_wrap.c lasso.py: $(SWIG_I_FILES)
	$(SWIG) -v -python -module lasso -o lasso_wrap.c $(top_srcdir)/swig/Lasso.i
	cp lasso_wrap.c lasso_wrap.c.bak
	sed -e 's/^  int res = 0;$$//' \
			< lasso_wrap.c.bak > lasso_wrap.c
	cp lasso_wrap.c lasso_wrap.c.bak
	sed -e 's/\/\*  if (val) \*val = PyObject_IsTrue(obj); return 1; \*\//int res = 0;/' \
			< lasso_wrap.c.bak > lasso_wrap.c
	cp lasso_wrap.c lasso_wrap.c.bak
	grep -q "int res =" lasso_wrap.c || \
		sed -e 's/if (obj == Py_True) /int res = 0; if (obj == Py_True) /' \
			< lasso_wrap.c.bak > lasso_wrap.c

SWIG_OUTPUTS = lasso_wrap.c lasso.py

clean-local:
	-rm lasso_wrap.c.bak

# In distribution, swig generated files are present.
EXTRA_DIST = $(SWIG_OUTPUTS)

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)
