XMLSOURCES = \
	py_lib_authentication_statement.c \
	py_lib_authn_request.c \
	py_lib_federation_termination_notification.c \
	py_lib_logout_request.c \
	py_lib_logout_response.c \
	py_lib_name_identifier_mapping_request.c \
	py_lib_name_identifier_mapping_response.c \
	py_lib_register_name_identifier_request.c \
	py_saml_assertion.c \
	py_saml_authentication_statement.c \
	py_saml_name_identifier.c \
	py_samlp_response.c \
	py_xml.c

noinst_LTLIBRARIES = libxml.la
libxml_la_SOURCES = $(XMLSOURCES)

INCLUDES = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/lasso \
	$(LASSO_DEFINES) \
	$(LASSO_CFLAGS) \
	$(PY_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	$(XMLSOURCES) \
	py_lib_authentication_statement.h \
	py_lib_authn_request.h \
	py_lib_federation_termination_notification.h \
	py_lib_logout_request.h \
	py_lib_logout_response.h \
	py_lib_name_identifier_mapping_request.h \
	py_lib_name_identifier_mapping_response.h \
	py_lib_register_name_identifier_request.h \
	py_saml_assertion.h \
	py_saml_authentication_statement.h \
	py_saml_name_identifier.h \
	py_samlp_response.h \
	py_xml.h

