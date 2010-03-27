EXTRA_DIST = xml_saml2.h
MAINTAINERCLEANFILES = Makefile.in
liblassoincludedir = $(includedir)/lasso/xml/saml-2.0

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml-saml2.la

liblasso_xml_saml2_la_SOURCES = \
	saml2_action.c \
	saml2_advice.c \
	saml2_assertion.c \
	saml2_attribute.c \
	saml2_attribute_statement.c \
	saml2_attribute_value.c \
	saml2_audience_restriction.c \
	saml2_authn_context.c \
	saml2_authn_statement.c \
	saml2_authz_decision_statement.c \
	saml2_base_idabstract.c \
	saml2_condition_abstract.c \
	saml2_conditions.c \
	saml2_encrypted_element.c \
	saml2_evidence.c \
	saml2_key_info_confirmation_data.c \
	saml2_name_id.c \
	saml2_one_time_use.c \
	saml2_proxy_restriction.c \
	saml2_statement_abstract.c \
	saml2_subject.c \
	saml2_subject_confirmation.c \
	saml2_subject_confirmation_data.c \
	saml2_subject_locality.c \
	samlp2_artifact_resolve.c \
	samlp2_artifact_response.c \
	samlp2_assertion_id_request.c \
	samlp2_attribute_query.c \
	samlp2_authn_query.c \
	samlp2_authn_request.c \
	samlp2_authz_decision_query.c \
	samlp2_extensions.c \
	samlp2_idp_entry.c \
	samlp2_idp_list.c \
	samlp2_logout_request.c \
	samlp2_logout_response.c \
	samlp2_manage_name_id_request.c \
	samlp2_manage_name_id_response.c \
	samlp2_name_id_mapping_request.c \
	samlp2_name_id_mapping_response.c \
	samlp2_name_id_policy.c \
	samlp2_request_abstract.c \
	samlp2_requested_authn_context.c \
	samlp2_response.c \
	samlp2_scoping.c \
	samlp2_status.c \
	samlp2_status_code.c \
	samlp2_status_detail.c \
	samlp2_status_response.c \
	samlp2_subject_query_abstract.c \
	samlp2_terminate.c

liblassoinclude_HEADERS = \
	saml2_action.h \
	saml2_advice.h \
	saml2_assertion.h \
	saml2_attribute.h \
	saml2_attribute_statement.h \
	saml2_attribute_value.h \
	saml2_audience_restriction.h \
	saml2_authn_context.h \
	saml2_authn_statement.h \
	saml2_authz_decision_statement.h \
	saml2_base_idabstract.h \
	saml2_condition_abstract.h \
	saml2_conditions.h \
	saml2_encrypted_element.h \
	saml2_evidence.h \
	saml2_key_info_confirmation_data.h \
	saml2_name_id.h \
	saml2_one_time_use.h \
	saml2_proxy_restriction.h \
	saml2_statement_abstract.h \
	saml2_subject_confirmation_data.h \
	saml2_subject_confirmation.h \
	saml2_subject.h \
	saml2_subject_locality.h \
	samlp2_artifact_resolve.h \
	samlp2_artifact_response.h \
	samlp2_assertion_id_request.h \
	samlp2_attribute_query.h \
	samlp2_authn_query.h \
	samlp2_authn_request.h \
	samlp2_authz_decision_query.h \
	samlp2_extensions.h \
	samlp2_idp_entry.h \
	samlp2_idp_list.h \
	samlp2_logout_request.h \
	samlp2_logout_response.h \
	samlp2_manage_name_id_request.h \
	samlp2_manage_name_id_response.h \
	samlp2_name_id_mapping_request.h \
	samlp2_name_id_mapping_response.h \
	samlp2_name_id_policy.h \
	samlp2_request_abstract.h \
	samlp2_requested_authn_context.h \
	samlp2_response.h \
	samlp2_scoping.h \
	samlp2_status_code.h \
	samlp2_status_detail.h \
	samlp2_status.h \
	samlp2_status_response.h \
	samlp2_subject_query_abstract.h \
	samlp2_terminate.h \
	saml2_strings.h \
	saml2_xsd.h
