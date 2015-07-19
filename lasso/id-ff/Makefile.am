MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/id-ff

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-id-ff.la

liblasso_id_ff_la_SOURCES = \
	defederation.c \
	federation.c \
	identity.c \
	lecp.c \
	login.c \
	logout.c \
	name_identifier_mapping.c \
	name_registration.c \
	profile.c \
	provider.c \
	session.c \
	server.c

lasso_private_h_sources = \
	identityprivate.h \
	profileprivate.h \
	providerprivate.h \
	serverprivate.h \
	sessionprivate.h \
	logoutprivate.h \
	loginprivate.h

liblassoinclude_HEADERS = \
	defederation.h \
	federation.h \
	identity.h \
	lecp.h \
	login.h \
	logout.h \
	name_identifier_mapping.h \
	name_registration.h \
	profile.h \
	provider.h \
	server.h \
	session.h

EXTRA_DIST = $(lasso_private_h_sources)
