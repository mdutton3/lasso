INCLUDES = -I$(top_srcdir)

pythondir= $(PY_SITE_PACKAGES)
python_DATA = lasso.py
python_LTLIBRARIES = _lasso.la

PYTHON_PACKAGE=lasso

_lasso_la_SOURCES = $(PYTHON_PACKAGE)_wrap.c

_lasso_la_CFLAGS =	$(LASSO_CFLAGS) \
			-DSWIG_COBJECT_TYPES \
			$(PY_CFLAGS)

_lasso_la_LIBADD =	$(top_builddir)/lasso/liblasso.la \
			$(LASSO_LIBS)

_lasso_la_LDFLAGS =	-no-undefined \
			-module -avoid-version

$(PYTHON_PACKAGE)_wrap.c $(PYTHON_PACKAGE).py: $(top_srcdir)/swig/Lasso.i
	$(SWIG) -v -python -module $(PYTHON_PACKAGE) -o $(PYTHON_PACKAGE)_wrap.c $<

# Dirty hack, another better way ?
$(DEPDIR)/_$(PYTHON_PACKAGE)_la-$(PYTHON_PACKAGE)_wrap.Plo:
	mkdir -p $(DEPDIR)
	echo "#dummy" > $(DEPDIR)/_$(PYTHON_PACKAGE)_la-$(PYTHON_PACKAGE)_wrap.Plo

SWIG_OUTPUTS = $(PYTHON_PACKAGE)_wrap.c $(PYTHON_PACKAGE).py


# In distribution, swig generated files are present.
EXTRA_DIST = $(SWIG_OUTPUTS)

# In case of....
CLEANFILES = *.pyc

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES = $(SWIG_OUTPUTS)

