liblassoincludedir = $(includedir)/lasso/id-wsf

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

lasso_private_h_sources = \
	data_service_private.h \
	wsf_profile_private.h

if WSF_ENABLED
noinst_LTLIBRARIES = liblasso-id-wsf.la
WSF_C_FILES = \
	authentication.c \
	discovery.c \
	interaction_profile_service.c \
	personal_profile_service.c \
	data_service.c \
	wsf_profile.c	

WSF_H_FILES = \
	authentication.h \
	discovery.h \
	identity.h \
	interaction_profile_service.h \
	personal_profile_service.h \
	data_service.h \
	wsf_profile.h
endif

liblasso_id_wsf_la_SOURCES = $(WSF_C_FILES)

liblassoinclude_HEADERS = $(WSF_H_FILES)

EXTRA_DIST = $(lasso_private_h_sources)
