liblassoincludedir = $(includedir)/lasso/protocols/elements

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-elements.la

liblasso_elements_la_SOURCES = \
	assertion.c \
	authentication_statement.c

liblassoinclude_HEADERS = \
	assertion.h \
	authentication_statement.h
