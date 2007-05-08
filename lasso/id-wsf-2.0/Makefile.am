liblassoincludedir = $(includedir)/lasso/id-wsf-2.0

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

lasso_private_h_sources = \
	wsf2_profile_private.h

noinst_LTLIBRARIES = liblasso-id-wsf2.la

liblasso_id_wsf2_la_SOURCES = \
	discovery.c \
	wsf2_profile.c

liblassoinclude_HEADERS = \
	discovery.h \
	wsf2_profile.h \
	identity.h \
	server.h \
	session.h

EXTRA_DIST = $(lasso_private_h_sources)
