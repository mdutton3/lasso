MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/xml/ws

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml-ws.la

liblasso_xml_ws_la_SOURCES = \
	wsa_attributed_any.c \
	wsa_attributed_qname.c \
	wsa_attributed_unsigned_long.c \
	wsa_attributed_uri.c \
	wsa_endpoint_reference.c \
	wsa_metadata.c \
	wsa_problem_action.c \
	wsa_reference_parameters.c \
	wsa_relates_to.c \
	wsse_embedded.c \
	wsse_reference.c \
	wsse_security_header.c \
	wsse_security_token_reference.c \
	wsse_transformation_parameters.c \
	wsse_username_token.c \
	wsu_timestamp.c

liblassoinclude_HEADERS = \
	wsa_attributed_any.h \
	wsa_attributed_qname.h \
	wsa_attributed_unsigned_long.h \
	wsa_attributed_uri.h \
	wsa_endpoint_reference.h \
	wsa_metadata.h \
	wsa_problem_action.h \
	wsa_reference_parameters.h \
	wsa_relates_to.h \
	wsse_embedded.h \
	wsse_reference.h \
	wsse_security_header.h \
	wsse_security_token_reference.h \
	wsse_transformation_parameters.h \
	wsse_username_token.h \
	wsu_timestamp.h \
	xml_ws.h

