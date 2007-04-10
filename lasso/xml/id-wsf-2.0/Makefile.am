liblassoincludedir = $(includedir)/lasso/xml/id-wsf-2.0

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml-id-wsf2.la

liblasso_xml_id_wsf2_la_SOURCES = \
	disco_endpoint_context.c \
	disco_options.c \
	disco_query.c \
	disco_query_response.c \
	disco_service_context.c \
	disco_service_metadata.c \
	disco_svc_md_register.c \
	soap_binding_framework.c

liblassoinclude_HEADERS = \
	disco_endpoint_context.h \
	disco_options.h \
	disco_query.h \
	disco_query_response.h \
	disco_service_context.h \
	disco_service_metadata.h \
	disco_svc_md_register.h \
	soap_binding_framework.h
