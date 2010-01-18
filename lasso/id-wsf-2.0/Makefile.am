MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/id-wsf-2.0

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-id-wsf2.la

lasso_private_h_sources = \
	private.h \
	serverprivate.h \
	sessionprivate.h \
	idwsf2_helper.h

liblasso_id_wsf2_la_SOURCES = \
	server.c \
	session.c \
	identity.c \
	discovery.c \
	data_service.c \
	profile.c \
	saml2_login.c \
	soap_binding.c \
	idwsf2_helper.c

liblassoinclude_HEADERS = \
	id_wsf_2.h \
	discovery.h \
	data_service.h \
	profile.h \
	identity.h \
	server.h \
	session.h \
	soap_binding.h \
	saml2_login.h

EXTRA_DIST = $(lasso_private_h_sources)
