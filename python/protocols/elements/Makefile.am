ELEMSOURCES = py_assertion.c py_authentication_statement.c

noinst_LTLIBRARIES = libelements.la
libelements_la_SOURCES = $(ELEMSOURCES)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS) \
	$(NULL)


EXTRA_DIST = $(ELEMSOURCES) py_assertion.h py_authentication_statement.h
