liblassoincludedir = $(includedir)/lasso/id-wsf

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-id-wsf.la

liblasso_id_wsf_la_SOURCES = \
	abstract_service.c \
	discovery.c \
	interaction_profile_service.c \
	profile_service.c \
	wsf_profile.c	

liblassoinclude_HEADERS = \
	abstract_service.h \
	discovery.h \
	interaction_profile_service.h \
	profile_service.h \
	wsf_profile.h
