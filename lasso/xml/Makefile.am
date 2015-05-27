MAINTAINERCLEANFILES = Makefile.in
SUBDIRS = saml-2.0 soap-1.1 dsig ecp
if WSF_ENABLED
SUBDIRS += id-wsf-2.0 ws
endif

liblassoincludedir = $(includedir)/lasso/xml

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(LASSO_CORE_CFLAGS) \
	-DG_LOG_DOMAIN=\"lasso\"

noinst_LTLIBRARIES = liblasso-xml.la

if WSF_ENABLED
WSF_C_FILES = \
	disco_authenticate_requester.c \
	disco_authenticate_session_context.c \
	disco_authorize_requester.c \
	disco_credentials.c \
	disco_description.c \
	disco_encrypt_resource_id.c \
	disco_encrypted_resource_id.c \
	disco_generate_bearer_token.c \
	disco_insert_entry.c \
	disco_modify.c \
	disco_modify_response.c \
	disco_options.c \
	disco_query.c \
	disco_query_response.c \
	disco_remove_entry.c \
	disco_requested_service_type.c \
	disco_resource_id.c \
	disco_resource_offering.c \
	disco_send_single_logout.c \
	disco_service_instance.c \
	dst_data.c \
	dst_modification.c \
	dst_modify.c \
	dst_modify_response.c \
	dst_new_data.c \
	dst_query.c \
	dst_query_item.c \
	dst_query_response.c \
	is_help.c \
	is_inquiry.c \
	is_inquiry_element.c \
	is_interaction_request.c \
	is_interaction_response.c \
	is_interaction_statement.c \
	is_item.c \
	is_parameter.c \
	is_redirect_request.c \
	is_select.c \
	is_text.c \
	is_user_interaction.c \
	sa_credentials.c \
	sa_parameter.c \
	sa_password_transforms.c \
	sa_transform.c \
	sa_sasl_request.c \
	sa_sasl_response.c \
	sec_resource_access_statement.c \
	soap_binding_consent.c \
	soap_binding_correlation.c \
	soap_binding_processing_context.c \
	soap_binding_provider.c \
	soap_binding_usage_directive.c \
	soap_binding_ext_credential.c \
	soap_binding_ext_credentials_context.c \
	soap_binding_ext_service_instance_update.c \
	soap_binding_ext_timeout.c \
	soap_binding.c \
	utility_status.c

WSF_H_FILES = \
	idwsf_strings.h \
	disco_authenticate_requester.h \
	disco_authenticate_session_context.h \
	disco_authorize_requester.h \
	disco_credentials.h \
	disco_description.h \
	disco_encrypt_resource_id.h \
	disco_encrypted_resource_id.h \
	disco_generate_bearer_token.h \
	disco_insert_entry.h \
	disco_modify.h \
	disco_modify_response.h \
	disco_options.h \
	disco_query.h \
	disco_query_response.h \
	disco_remove_entry.h \
	disco_requested_service_type.h \
	disco_resource_id.h \
	disco_resource_offering.h \
	disco_send_single_logout.h \
	disco_service_instance.h \
	dst_data.h \
	dst_modification.h \
	dst_modify.h \
	dst_modify_response.h \
	dst_new_data.h \
	dst_query.h \
	dst_query_item.h \
	dst_query_response.h \
	is_help.h \
	is_inquiry.h \
	is_inquiry_element.h \
	is_interaction_request.h \
	is_interaction_response.h \
	is_interaction_statement.h \
	is_item.h \
	is_parameter.h \
	is_redirect_request.h \
	is_select.h \
	is_text.h \
	is_user_interaction.h \
	sa_credentials.h \
	sa_parameter.h \
	sa_password_transforms.h \
	sa_transform.h \
	sa_sasl_request.h \
	sa_sasl_response.h \
	sec_resource_access_statement.h \
	soap_binding_consent.h \
	soap_binding_correlation.h \
	soap_binding_processing_context.h \
	soap_binding_provider.h \
	soap_binding_usage_directive.h \
	soap_binding_ext_credential.h \
	soap_binding_ext_credentials_context.h \
	soap_binding_ext_service_instance_update.h \
	soap_binding_ext_timeout.h \
	soap_binding.h \
	utility_status.h
endif

liblasso_xml_la_SOURCES = \
	tools.c \
	xml.c \
	lib_assertion.c	\
	lib_authentication_statement.c \
	lib_authn_context.c	\
	lib_authn_request.c	\
	lib_authn_request_envelope.c	\
	lib_authn_response.c \
	lib_authn_response_envelope.c \
	lib_federation_termination_notification.c \
	lib_idp_entries.c	\
	lib_idp_entry.c	\
	lib_idp_list.c	\
	lib_logout_request.c \
	lib_logout_response.c \
	lib_name_identifier_mapping_request.c \
	lib_name_identifier_mapping_response.c \
	lib_register_name_identifier_request.c \
	lib_register_name_identifier_response.c \
	lib_request_authn_context.c	\
	lib_scoping.c \
	lib_status_response.c \
	lib_subject.c \
	misc_text_node.c \
	paos_request.c \
	paos_response.c \
	saml_advice.c \
	saml_assertion.c \
	saml_attribute.c \
	saml_attribute_designator.c \
	saml_attribute_statement.c \
	saml_attribute_value.c \
	saml_audience_restriction_condition.c \
	saml_authentication_statement.c \
	saml_authority_binding.c \
	saml_condition_abstract.c \
	saml_conditions.c \
	saml_name_identifier.c \
	saml_statement_abstract.c \
	saml_subject.c \
	saml_subject_confirmation.c \
	saml_subject_locality.c \
	saml_subject_statement.c \
	saml_subject_statement_abstract.c \
	samlp_request.c \
	samlp_request_abstract.c \
	samlp_response.c \
	samlp_response_abstract.c \
	samlp_status.c \
	samlp_status_code.c \
	$(WSF_C_FILES)

liblassoinclude_HEADERS = \
	strings.h \
	xml.h \
	lib_assertion.h	\
	lib_authentication_statement.h \
	lib_authn_context.h	\
	lib_authn_request.h	\
	lib_authn_request_envelope.h	\
	lib_authn_response.h \
	lib_authn_response_envelope.h \
	lib_federation_termination_notification.h \
	lib_idp_entries.h	\
	lib_idp_entry.h	\
	lib_idp_list.h	\
	lib_logout_request.h \
	lib_logout_response.h \
	lib_name_identifier_mapping_request.h \
	lib_name_identifier_mapping_response.h \
	lib_register_name_identifier_request.h \
	lib_register_name_identifier_response.h \
	lib_request_authn_context.h	\
	lib_scoping.h \
	lib_status_response.h \
	lib_subject.h \
	misc_text_node.h \
	paos_request.h \
	paos_response.h \
	saml_advice.h \
	saml_assertion.h \
	saml_attribute.h \
	saml_attribute_designator.h \
	saml_attribute_statement.h \
	saml_attribute_value.h \
	saml_audience_restriction_condition.h \
	saml_authentication_statement.h \
	saml_authority_binding.h \
	saml_condition_abstract.h \
	saml_conditions.h \
	saml_name_identifier.h \
	saml_statement_abstract.h \
	saml_subject.h \
	saml_subject_confirmation.h \
	saml_subject_locality.h \
	saml_subject_statement.h \
	saml_subject_statement_abstract.h \
	samlp_request.h \
	samlp_request_abstract.h \
	samlp_response.h \
	samlp_response_abstract.h \
	samlp_status.h \
	samlp_status_code.h \
	xml_enc.h \
	tools.h \
	$(WSF_H_FILES)

lasso_private_h_sources = \
	private.h

EXTRA_DIST = $(lasso_private_h_sources) xml_idff.h xml_idwsf.h
