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
	federation_termination_notification.c \
	logout_request.c \
	logout_response.c \
	register_name_identifier_response.c \
	register_name_identifier_request.c \
	protocol.c

liblassoinclude_HEADERS = \
	federation_termination_notification.h \
	logout_request.h \
	logout_response.h \
	register_name_identifier_response.h \
	register_name_identifier_request.h \
	protocols.h \
	protocol.h