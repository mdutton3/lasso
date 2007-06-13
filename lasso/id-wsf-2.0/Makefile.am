liblassoincludedir = $(includedir)/lasso/id-wsf-2.0

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-id-wsf2.la

liblasso_id_wsf2_la_SOURCES = \
	discovery.c \
	data_service.c \
	profile.c

liblassoinclude_HEADERS = \
	discovery.h \
	data_service.h \
	profile.h \
	identity.h \
	server.h \
	session.h

