liblassoincludedir = $(includedir)/lasso/id-wsf

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-id-wsf.la

liblasso_id_wsf_la_SOURCES = \
	wsf_profile.c

liblassoinclude_HEADERS = \
	wsf_profile.h