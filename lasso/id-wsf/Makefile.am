liblassoincludedir = $(includedir)/lasso/id-wsf

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-id-wsf.la

if WSF_ENABLED
WSF_C_FILES = \
	discovery.c \
	interaction_profile_service.c \
	profile_service.c \
	wsf_profile.c	

WSF_H_FILES = \
	discovery.h \
	interaction_profile_service.h \
	profile_service.h \
	wsf_profile.h
endif

if WSF_AUTH_ENABLED
WSF_AUTH_C_FILES = authentication.c
WSF_AUTH_H_FILES = authentication.h
endif

liblasso_id_wsf_la_SOURCES = \
	$(WSF_AUTH_C_FILES) \
	$(WSF_C_FILES)

liblassoinclude_HEADERS = \
	$(WSF_AUTH_H_FILES) \
	$(WSF_H_FILES)

EXTRA_DIST = $(WSF_AUTH_C_FILES) $(WSF_AUTH_H_FILES)

