MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/saml-2.0

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-saml-20.la

liblasso_saml_20_la_SOURCES = \
	assertion_query.c \
	ecp.c \
	federation.c \
	profile.c \
	provider.c \
	login.c \
	logout.c \
	name_id_management.c \
	server.c \
	saml2_helper.c

liblassoinclude_HEADERS = \
	assertion_query.h \
	ecp.h \
	profile.h \
	name_id_management.h \
	provider.h \
	saml2_helper.h

lasso_private_h_sources = \
	federationprivate.h \
	profileprivate.h \
	providerprivate.h \
	loginprivate.h \
	logoutprivate.h \
	serverprivate.h \
	ecpprivate.h

EXTRA_DIST = $(lasso_private_h_sources)
