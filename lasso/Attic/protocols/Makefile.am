liblassoincludedir = $(includedir)/lasso/protocols

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(GLIB_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(XMLSEC1_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-protocols.la

liblasso_protocols_la_SOURCES = \
	protocol.c \
	logout_request.c \
	logout_response.c \
	#sso_and_federation_authn_request.c

liblassoinclude_HEADERS = \
	protocols.h \
	protocol.h \
	logout_request.h \
	logout_response.h \
	#sso_and_federation_authn_request.h
