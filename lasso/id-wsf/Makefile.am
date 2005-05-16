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
	profile_service.c \
	wsf_profile.c	

WSF_H_FILES = \
	authentication.h \
	discovery.h \
	interaction_profile_service.h \
	profile_service.h \
	wsf_profile.h
endif

liblasso_id_wsf_la_SOURCES = $(WSF_C_FILES)

liblassoinclude_HEADERS = $(WSF_H_FILES)

