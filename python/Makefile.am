SUBDIRS = doc environs examples protocols tests xml

lassomod_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/lasso/.libs

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS)

pythondir = $(PY_SITE_PACKAGES)
python_LTLIBRARIES = lassomod.la
python_DATA = lasso.py lasso_strings.py

mylibs = $(top_builddir)/lasso/liblasso.la

lassomod_la_SOURCES = lassomod.c  py_lasso.c  utils.c  wrap_objs.c
lassomod_la_LIBADD = $(mylibs) \
	./protocols/elements/libelements.a \
	./protocols/libprotocols.a \
	./xml/libxml.a \
	./environs/libenvirons.a

EXTRA_DIST = lassomod.h  py_lasso.h  utils.h  wrap_objs.h \
		generator_lasso_strings.py  lasso.py  lasso_strings.py \
		lassomod.c  py_lasso.c  utils.c  wrap_objs.c

