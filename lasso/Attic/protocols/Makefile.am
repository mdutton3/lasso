SUBDIRS = elements

liblassoincludedir = $(includedir)/lasso/protocols

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-protocols.la

liblasso_protocols_la_LIBADD = \
	$(top_builddir)/lasso/protocols/elements/liblasso-elements.la \
	$(LASSO_LIBS)

liblasso_protocols_la_SOURCES = \
	protocols.c \
	artifact.c \
	authn_request.c \
	authn_request_envelope.c \
	authn_response.c \
	authn_response_envelope.c \
	federation.c \
	federation_termination_notification.c \
	logout_request.c \
	logout_response.c \
	name_identifier_mapping_request.c \
	name_identifier_mapping_response.c \
	provider.c \
	register_name_identifier_request.c \
	register_name_identifier_response.c \
	request.c \
	response.c

liblassoinclude_HEADERS = \
	protocols.h \
	artifact.h \
	authn_request.h \
	authn_request_envelope.h \
	authn_response.h \
	authn_response_envelope.h \
	federation.h \
	federation_termination_notification.h \
	logout_request.h \
	logout_response.h \
	name_identifier_mapping_request.h \
	name_identifier_mapping_response.h \
	provider.h \
	register_name_identifier_request.h \
	register_name_identifier_response.h \
	request.h \
	response.h
