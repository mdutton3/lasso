noinst_LIBRARIES = libelements.a

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = libelements.a
libelements_a_SOURCES = py_assertion.c py_authentication_statement.c

EXTRA_DIST = py_assertion.h py_authentication_statement.h
