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
	disco_svc_metadata.c \
	disco_svc_md_association_add.c \
	disco_svc_md_association_add_response.c \
	disco_svc_md_register.c \
	disco_svc_md_register_response.c \
	disco_abstract.c \
	disco_providerid.c \
	disco_service_type.c \
	soap_binding_framework.c \
	util_status.c

liblassoinclude_HEADERS = \
	disco_endpoint_context.h \
	disco_options.h \
	disco_query.h \
	disco_query_response.h \
	disco_service_context.h \
	disco_svc_metadata.h \
	disco_svc_md_association_add.h \
	disco_svc_md_association_add_response.h \
	disco_svc_md_register.h \
	disco_svc_md_register_response.h \
	disco_abstract.h \
	disco_providerid.h \
	disco_service_type.h \
	soap_binding_framework.h \
	util_status.h
