SUBDIRS = elements

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

liblasso_protocols_la_LIBADD = \
	$(top_builddir)/lasso/protocols/elements/liblasso-elements.la \
	$(GLIB_LIBS) \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(XMLSEC1_LIBS)

liblasso_protocols_la_SOURCES = \
	protocols.c \
	authn_request.c \
	authn_response.c \
	federation_termination_notification.c \
	logout_request.c \
	logout_response.c \
	name_identifier_mapping_request.c \
	name_identifier_mapping_response.c \
	register_name_identifier_response.c \
	register_name_identifier_request.c

liblassoinclude_HEADERS = \
	protocols.h \
	authn_request.h \
	authn_response.h \
	federation_termination_notification.h \
	logout_request.h \
	logout_response.h \
	name_identifier_mapping_request.h \
	name_identifier_mapping_response.h \
	register_name_identifier_response.h \
	register_name_identifier_request.h
