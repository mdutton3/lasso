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
	federation_termination_notification.c \
	logout.c \
	register_name_identifier.c \
	single_sign_on_and_federation.c \
	ssoaf_authn_request.c

liblassoinclude_HEADERS = \
	protocols.h \
	protocol.h \
	federation_termination_notification.h \
	logout.h \
	register_name_identifier.h \
	single_sign_on_and_federation.h \
	ssoaf_authn_request.h
