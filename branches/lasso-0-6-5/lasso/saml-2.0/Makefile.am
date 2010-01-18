liblassoincludedir = $(includedir)/lasso/saml-2.0

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	-I$(top_builddir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-saml-20.la

liblasso_saml_20_la_SOURCES = \
	federation.c \
	profile.c \
	provider.c \
	login.c \
	logout.c

lasso_private_h_sources = \
	federationprivate.h \
	profileprivate.h \
	providerprivate.h \
	loginprivate.h \
	logoutprivate.h

EXTRA_DIST = $(lasso_private_h_sources)
