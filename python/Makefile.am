NULL=

INCLUDES=-I$(top_srcdir)

pythondir= $(PY_SITE_PACKAGES)
python_DATA=lassomod.py
python_LTLIBRARIES=_lassomod.la

PYTHON_PACKAGE=lassomod
_lassomod_la_SOURCES=$(PYTHON_PACKAGE)_wrap.c \
			$(top_srcdir)/swig/Lasso.c
_lassomod_la_CFLAGS=	$(LASSO_CFLAGS) \
			-DSWIG_COBJECT_TYPES \
			$(PY_CFLAGS) \
			$(NULL)
_lassomod_la_LIBADD=	$(top_srcdir)/lasso/liblasso.la \
			$(LASSO_LIBS) \
			$(NULL)
_lassomod_la_LDFLAGS=	-no-undefined \
			-module -avoid-version \
			-version-info @LASSO_VERSION_INFO@ \
				$(NULL)

$(PYTHON_PACKAGE)_wrap.c $(PYTHON_PACKAGE).py: $(srcdir)/../swig/Lasso.i
	$(SWIG) -v -python -module $(PYTHON_PACKAGE) -o $(PYTHON_PACKAGE)_wrap.c $<

# Dirty hack, another better way ?
.deps/_$(PYTHON_PACKAGE)_la-$(PYTHON_PACKAGE)_wrap.Plo:
	mkdir -p .deps
	echo "#dummy" > .deps/_$(PYTHON_PACKAGE)_la-$(PYTHON_PACKAGE)_wrap.Plo

SWIG_OUTPUTS=$(PYTHON_PACKAGE)_wrap.c $(PYTHON_PACKAGE).py


SUBDIRS= \
	$(NULL)

# In distribution, swig generated files are present.
EXTRA_DIST= $(SWIG_OUTPUTS)\
            $(NULL)

# In case of....
CLEANFILES=lassomod.pyc

# Maintainer clean the swig generated files, because he/she maintains them.
MAINTAINERCLEANFILES=$(SWIG_OUTPUTS)

