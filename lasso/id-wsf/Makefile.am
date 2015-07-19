MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/id-wsf

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

lasso_private_h_sources = \
	wsf_profile_private.h \
	id_ff_extensions_private.h

if WSF_ENABLED
noinst_LTLIBRARIES = liblasso-id-wsf.la
WSF_C_FILES = \
	authentication.c \
	discovery.c \
	interaction_profile_service.c \
	personal_profile_service.c \
	data_service.c \
	wsf_profile.c \
	wsf_utils.c \
	id_ff_extensions.c

WSF_H_FILES = \
	id_wsf.h \
	authentication.h \
	discovery.h \
	interaction_profile_service.h \
	personal_profile_service.h \
	data_service.h \
	wsf_profile.h \
	wsf_utils.h \
	id_ff_extensions.h
endif

liblasso_id_wsf_la_SOURCES = $(WSF_C_FILES)

liblassoinclude_HEADERS = $(WSF_H_FILES)

EXTRA_DIST = $(lasso_private_h_sources)
