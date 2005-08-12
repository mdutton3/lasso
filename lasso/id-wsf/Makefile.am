liblassoincludedir = $(includedir)/lasso/id-wsf

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

if WSF_ENABLED
noinst_LTLIBRARIES = liblasso-id-wsf.la
WSF_C_FILES = \
	authentication.c \
	discovery.c \
	interaction_profile_service.c \
	personal_profile_service.c \
	profile_service.c \
	wsf_profile.c	

lasso_private_h_sources = \
	profile_service_private.h

WSF_H_FILES = \
	authentication.h \
	discovery.h \
	identity.h \
	interaction_profile_service.h \
	personal_profile_service.h \
	profile_service.h \
	wsf_profile.h
endif

liblasso_id_wsf_la_SOURCES = $(WSF_C_FILES)

liblassoinclude_HEADERS = $(WSF_H_FILES)

EXTRA_DIST = $(lasso_private_h_sources)
