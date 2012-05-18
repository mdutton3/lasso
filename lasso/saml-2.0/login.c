/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/saml-2.0/loginprivate.h>
#include <lasso/saml-2.0/profileprivate.h>
#include <lasso/saml-2.0/federationprivate.h>

#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/serverprivate.h>
#include <lasso/id-ff/login.h>
#include <lasso/id-ff/identityprivate.h>
#include <lasso/id-ff/sessionprivate.h>
#include <lasso/id-ff/loginprivate.h>

#include <lasso/xml/xml_enc.h>

#include <lasso/xml/saml-2.0/samlp2_authn_request.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <lasso/xml/saml-2.0/saml2_audience_restriction.h>
#include <lasso/xml/saml-2.0/saml2_authn_statement.h>
#include <lasso/xml/saml-2.0/saml2_encrypted_element.h>
#include <lasso/xml/saml-2.0/saml2_attribute.h>
#include <lasso/xml/saml-2.0/saml2_attribute_statement.h>
#include <lasso/xml/saml-2.0/saml2_attribute_value.h>
#include <lasso/xml/saml-2.0/saml2_name_id.h>

#ifdef LASSO_WSF_ENABLED
#include <lasso/id-wsf-2.0/identity.h>
#include <lasso/id-wsf-2.0/server.h>
#include <lasso/id-wsf-2.0/session.h>
#include <lasso/xml/ws/wsa_endpoint_reference.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_metadata.h>
#include <lasso/xml/id-wsf-2.0/disco_abstract.h>
#include <lasso/xml/id-wsf-2.0/disco_provider_id.h>
#include <lasso/xml/id-wsf-2.0/disco_service_type.h>
#include <lasso/xml/id-wsf-2.0/disco_service_context.h>
#include <lasso/xml/id-wsf-2.0/disco_security_context.h>
#include <lasso/xml/id-wsf-2.0/sec_token.h>
#endif

#include "../utils.h"

static int lasso_saml20_login_process_federation(LassoLogin *login, gboolean is_consent_obtained);
static gboolean lasso_saml20_login_must_ask_for_consent_private(LassoLogin *login);
static gint lasso_saml20_login_process_response_status_and_assertion(LassoLogin *login);
static char* lasso_saml20_login_get_assertion_consumer_service_url(LassoLogin *login,
		LassoProvider *remote_provider);

gint
lasso_saml20_login_init_authn_request(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2RequestAbstract *request;

	if (http_method != LASSO_HTTP_METHOD_REDIRECT &&
			http_method != LASSO_HTTP_METHOD_POST &&
			http_method != LASSO_HTTP_METHOD_ARTIFACT_GET &&
			http_method != LASSO_HTTP_METHOD_ARTIFACT_POST &&
			http_method != LASSO_HTTP_METHOD_SOAP) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	login->http_method = http_method;

	profile->request = lasso_samlp2_authn_request_new();
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	request->ID = lasso_build_unique_id(32);
	lasso_assign_string(login->private_data->request_id, request->ID);
	request->Version = g_strdup("2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	LASSO_SAMLP2_AUTHN_REQUEST(request)->NameIDPolicy = LASSO_SAMLP2_NAME_ID_POLICY(
			lasso_samlp2_name_id_policy_new());
	LASSO_SAMLP2_AUTHN_REQUEST(request)->NameIDPolicy->Format =
		g_strdup(LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);
	LASSO_SAMLP2_AUTHN_REQUEST(request)->NameIDPolicy->SPNameQualifier =
		g_strdup(request->Issuer->content);


	if (http_method != LASSO_HTTP_METHOD_REDIRECT) {
		request->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
		if (profile->server->certificate) {
			request->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
		} else {
			request->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
		}
	}

	return 0;
}


gint
lasso_saml20_login_build_authn_request_msg(LassoLogin *login, LassoProvider *remote_provider)
{
	char *url;
	char *md_authnRequestsSigned;
	gboolean must_sign;
	LassoProfile *profile = LASSO_PROFILE(login);

	md_authnRequestsSigned = lasso_provider_get_metadata_one(
			LASSO_PROVIDER(profile->server), "AuthnRequestsSigned");
	must_sign = (md_authnRequestsSigned && strcmp(md_authnRequestsSigned, "true") == 0);
	g_free(md_authnRequestsSigned);

	if (login->http_method == LASSO_HTTP_METHOD_REDIRECT) {
		return lasso_saml20_build_http_redirect_query_simple(profile, profile->request,
				must_sign, "SingleSignOnService", FALSE);
	} else {
		/* POST, SOAP and Artifact-GET|POST */
		if (must_sign) {
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_file =
				g_strdup(profile->server->private_key);
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_password =
				g_strdup(profile->server->private_key_password);
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->certificate_file =
				g_strdup(profile->server->certificate);
		}

		if (login->http_method == LASSO_HTTP_METHOD_POST) {
			char *lareq = lasso_node_export_to_base64(profile->request);
			profile->msg_url = lasso_provider_get_metadata_one(
					remote_provider, "SingleSignOnService HTTP-POST");
			profile->msg_body = lareq;
		} else if (login->http_method == LASSO_HTTP_METHOD_SOAP) {
			const char *issuer;
			const char *responseConsumerURL;

			issuer = LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID;
			responseConsumerURL = \
				lasso_saml20_login_get_assertion_consumer_service_url(
						login, LASSO_PROVIDER(profile->server));
			profile->msg_url = NULL;
			profile->msg_body = lasso_node_export_to_paos_request(profile->request,
							issuer, responseConsumerURL,
							profile->msg_relayState);
		} else {
			/* artifact method */
			char *artifact = lasso_saml20_profile_generate_artifact(profile, 0);
			char *url_artifact = (char*)xmlURIEscapeStr((xmlChar*)artifact, NULL);
			url = lasso_provider_get_metadata_one(
					remote_provider, "SingleSignOnService HTTP-Artifact");
			if (login->http_method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
				gchar *query = g_strdup_printf("SAMLart=%s", url_artifact);
				profile->msg_url = lasso_concat_url_query(url, query);
				g_free(query);
				g_free(url);
			} else {
				/* TODO: ARTIFACT POST */
			}
			xmlFree(url_artifact);
		}
	}

	return 0;
}

int
lasso_saml20_login_process_authn_request_msg(LassoLogin *login, const char *authn_request_msg)
{
	LassoNode *request;
	LassoMessageFormat format;
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2StatusResponse *response;
	LassoSamlp2AuthnRequest *authn_request;
	gchar *protocol_binding;

	if (authn_request_msg == NULL) {
		if (profile->request == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
		}

		/* AuthnRequest already set by .._init_idp_initiated_authn_request */
		request = profile->request;
	} else {
		request = lasso_samlp2_authn_request_new();
		format = lasso_node_init_from_message(request, authn_request_msg);
		if (format == LASSO_MESSAGE_FORMAT_UNKNOWN ||
				format == LASSO_MESSAGE_FORMAT_ERROR) {
			return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
		}
		if (format == LASSO_MESSAGE_FORMAT_QUERY) {
			lasso_assign_new_string(profile->msg_relayState,
				lasso_get_relaystate_from_query(authn_request_msg));
		}
	}

	authn_request = LASSO_SAMLP2_AUTHN_REQUEST(request);

	profile->request = request;
	profile->remote_providerID = g_strdup(
			LASSO_SAMLP2_REQUEST_ABSTRACT(request)->Issuer->content);

	protocol_binding = authn_request->ProtocolBinding;
	if (protocol_binding == NULL) {
		/* protocol binding not set; so it will look into
		 * AssertionConsumingServiceIndex
		 * Also, if AssertionConsumerServiceIndex is not set in request,
		 * its value will be -1, which is just the right value to get
		 * default assertion consumer...  (convenient)
		 */
		gchar *binding;
		LassoProvider *remote_provider;
		int service_index = authn_request->AssertionConsumerServiceIndex;

		remote_provider = g_hash_table_lookup(profile->server->providers,
				profile->remote_providerID);
		if (remote_provider == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
		}

		binding = lasso_saml20_provider_get_assertion_consumer_service_binding(
				remote_provider, service_index);
		if (binding == NULL) {
			if (service_index == -1)
				return LASSO_LOGIN_ERROR_NO_DEFAULT_ENDPOINT;
		} else if (strcmp(binding, "HTTP-Artifact") == 0) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
		} else if (strcmp(binding, "HTTP-POST") == 0) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
		} else if (strcmp(binding, "HTTP-Redirect") == 0) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT;
		} else if (strcmp(binding, "SOAP") == 0) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
		} else if (strcmp(binding, "PAOS") == 0) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
		}
	} else if (strcmp(protocol_binding, LASSO_SAML2_METADATA_BINDING_ARTIFACT) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
	} else if (strcmp(protocol_binding, LASSO_SAML2_METADATA_BINDING_POST) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
	} else if (strcmp(protocol_binding, LASSO_SAML2_METADATA_BINDING_SOAP) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
	} else if (strcmp(protocol_binding, LASSO_SAML2_METADATA_BINDING_REDIRECT) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT;
	} else if (strcmp(protocol_binding, LASSO_SAML2_METADATA_BINDING_PAOS) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
	} else {
		message(G_LOG_LEVEL_CRITICAL,
				"unhandled protocol binding: %s", protocol_binding);
	}

	/* XXX: checks authn request signature */

	profile->response = lasso_samlp2_response_new();
	response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);
	response->ID = lasso_build_unique_id(32);
	response->Version = g_strdup("2.0");
	response->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	response->IssueInstant = lasso_get_current_time();
	response->InResponseTo = g_strdup(LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	/* XXX: adds signature */

	return 0;
}


gboolean
lasso_saml20_login_must_authenticate(LassoLogin *login)
{
	LassoSamlp2AuthnRequest *request;
	gboolean matched = TRUE;
	GList *assertions = NULL;
	LassoProfile *profile = LASSO_PROFILE(login);

	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);

	if (request->ForceAuthn == TRUE && request->IsPassive == FALSE)
		return TRUE;

	assertions = lasso_session_get_assertions(profile->session, NULL);
	if (request->RequestedAuthnContext) {
		char *comparison = request->RequestedAuthnContext->Comparison;
		GList *class_refs = request->RequestedAuthnContext->AuthnContextClassRef;
		char *class_ref;
		GList *t1, *t2;
		int compa;

		if (comparison == NULL || strcmp(comparison, "exact") == 0) {
			compa = 0;
		} else if (strcmp(comparison, "minimum") == 0) {
			message(G_LOG_LEVEL_CRITICAL, "'minimum' comparison is not implemented");
			compa = 0;
		} else if (strcmp(comparison, "better") == 0) {
			message(G_LOG_LEVEL_CRITICAL, "'better' comparison is not implemented");
			compa = 0;
		} else if (strcmp(comparison, "maximum") == 0) {
			message(G_LOG_LEVEL_CRITICAL, "'maximum' comparison is not implemented");
			compa = 0;
		}

		if (class_refs) {
			matched = FALSE;
		}

		for (t1 = class_refs; t1 && !matched; t1 = g_list_next(t1)) {
			class_ref = t1->data;
			for (t2 = assertions; t2 && !matched; t2 = g_list_next(t2)) {
				LassoSaml2Assertion *assertion;
				LassoSaml2AuthnStatement *as = NULL;
				char *method;
				GList *t3;

				if (LASSO_IS_SAML2_ASSERTION(t2->data) == FALSE) {
					continue;
				}

				assertion = t2->data;

				for (t3 = assertion->AuthnStatement; t3; t3 = g_list_next(t3)) {
					if (LASSO_IS_SAML2_AUTHN_STATEMENT(t3->data)) {
						as = t3->data;
						break;
					}
				}

				if (as == NULL)
					continue;

				if (as->AuthnContext == NULL)
					continue;

				method = as->AuthnContext->AuthnContextClassRef;

				if (compa == 0) { /* exact */
					if (strcmp(method, class_ref) == 0) {
						matched = TRUE;
						break;
					}
				} else if (compa == 1) { /* minimum */
					/* XXX: implement 'minimum' comparison */
				} else if (compa == 2) { /* better */
					/* XXX: implement 'better' comparison */
				} else if (compa == 3) { /* maximum */
					/* XXX: implement 'maximum' comparison */
				}
			}
		}

	} else {
		/* if nothing specific was asked; don't look for any
		 * particular assertions, one is enough
		 */
		matched = (profile->session != NULL && \
				g_hash_table_size(profile->session->assertions) > 0);
	}
	g_list_free(assertions);

	if (matched == FALSE && request->IsPassive == FALSE)
		return TRUE;

	if (profile->identity == NULL && request->IsPassive) {
		lasso_saml20_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_SAML2_STATUS_CODE_NO_PASSIVE);
		return FALSE;
	}

	return FALSE;

}

static gboolean
lasso_saml20_login_must_ask_for_consent_private(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2NameIDPolicy *name_id_policy;
	char *consent;
	LassoFederation *federation;
	char *name_id_sp_name_qualifier = NULL;
	LassoProvider *remote_provider;

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;

	if (name_id_policy) {
		char *format = name_id_policy->Format;
		if (strcmp(format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) == 0) {
			return FALSE;
		}
		if (name_id_policy->AllowCreate == FALSE) {
			return FALSE;
		}
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider->private_data->affiliation_id) {
		name_id_sp_name_qualifier = remote_provider->private_data->affiliation_id;
	} else {
		name_id_sp_name_qualifier = profile->remote_providerID;
	}

	if (profile->identity && profile->identity->federations) {
		/* search a federation in the identity */
		federation = g_hash_table_lookup(profile->identity->federations,
				name_id_sp_name_qualifier);
		if (federation) {
			return FALSE;
		}
	}

	consent = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Consent;
	if (consent == NULL)
		return FALSE;

	if (strcmp(consent, LASSO_SAML2_CONSENT_OBTAINED) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_SAML2_CONSENT_PRIOR) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_SAML2_CONSENT_IMPLICIT) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_SAML2_CONSENT_EXPLICIT) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_SAML2_CONSENT_UNAVAILABLE) == 0)
		return TRUE;

	if (strcmp(consent, LASSO_SAML2_CONSENT_INAPPLICABLE) == 0)
		return TRUE;

	return TRUE;
}

gboolean
lasso_saml20_login_must_ask_for_consent(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);

	if (LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->IsPassive)
		return FALSE;

	return lasso_saml20_login_must_ask_for_consent_private(login);
}

int
lasso_saml20_login_validate_request_msg(LassoLogin *login, gboolean authentication_result,
		gboolean is_consent_obtained)
{
	LassoProfile *profile;
	int ret = 0;

	profile = LASSO_PROFILE(login);

	if (authentication_result == FALSE) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return LASSO_LOGIN_ERROR_REQUEST_DENIED;
	}

	if (profile->signature_status == LASSO_DS_ERROR_INVALID_SIGNATURE) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return LASSO_LOGIN_ERROR_INVALID_SIGNATURE;
	}

	if (profile->signature_status == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST;
	}

	if (profile->signature_status == 0 && authentication_result == TRUE) {
		ret = lasso_saml20_login_process_federation(login, is_consent_obtained);
		if (ret == LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND) {
			lasso_saml20_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return ret;
		}
		/* Only possibility, consent not obtained. */
		if (ret) {
			lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
			return ret;
		}
	}

	lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_SUCCESS);

	return ret;
}

static int
lasso_saml20_login_process_federation(LassoLogin *login, gboolean is_consent_obtained)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2NameIDPolicy *name_id_policy;
	char *name_id_policy_format = NULL;
	LassoFederation *federation;
	char *name_id_sp_name_qualifier = NULL;
	LassoProvider *remote_provider;

	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	if (name_id_policy) {
		name_id_policy_format = name_id_policy->Format;
	} else {
		name_id_policy_format = LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT;
	}

	if (login->nameIDPolicy) {
		g_free(login->nameIDPolicy);
	}
	login->nameIDPolicy = g_strdup(name_id_policy_format);

	if (name_id_policy_format && strcmp(name_id_policy_format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) == 0) {
		return 0;
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider->private_data->affiliation_id) {
		name_id_sp_name_qualifier = remote_provider->private_data->affiliation_id;
	} else {
		name_id_sp_name_qualifier = profile->remote_providerID;
	}

	/* search a federation in the identity */
	federation = g_hash_table_lookup(profile->identity->federations, name_id_sp_name_qualifier);
	if (name_id_policy == NULL || name_id_policy->AllowCreate == FALSE) {
		if (LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy == NULL) {
			/* it tried to get a federation, it failed, this is not
			 * a problem */
			return 0;
		}
		/* a federation MUST exist */
		if (federation == NULL) {
			return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
		}
	}

	if (federation == NULL &&
			LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy == NULL) {
		/* it didn't find a federation, and name id policy was not
		 * specified, don't create a federation */
		return 0;
	}

	if (federation && LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy == NULL) {
		LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy = \
			LASSO_SAMLP2_NAME_ID_POLICY(lasso_samlp2_name_id_policy_new());
		LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy->Format =
			g_strdup(LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	}

	if (lasso_saml20_login_must_ask_for_consent_private(login) && !is_consent_obtained) {
		return LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
	}

	if (federation == NULL) {
		federation = lasso_federation_new(name_id_sp_name_qualifier);
		lasso_saml20_federation_build_local_name_identifier(federation,
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,
				NULL);
		LASSO_SAML2_NAME_ID(federation->local_nameIdentifier)->SPNameQualifier = g_strdup(
				name_id_sp_name_qualifier);
		lasso_identity_add_federation(profile->identity, federation);
	}

	profile->nameIdentifier = g_object_ref(federation->local_nameIdentifier);

	return 0;
}


#ifdef LASSO_WSF_ENABLED
static void
lasso_saml20_login_assertion_add_discovery(LassoLogin *login, LassoSaml2Assertion *assertion)
{
	GList *svcMDIDs;
	GList *svcMDs;
	LassoIdWsf2DiscoSvcMetadata *svcMD;
	LassoWsAddrEndpointReference *epr;
	LassoWsAddrMetadata *metadata;
	LassoSaml2AttributeStatement *attributeStatement;
	LassoSaml2Attribute *attribute;
	LassoSaml2AttributeValue *attributeValue;
	LassoIdWsf2DiscoSecurityContext *security_context;
	LassoIdWsf2SecToken *sec_token;
	LassoSaml2Assertion *assertion_identity_token;
	LassoIdWsf2DiscoServiceContext *service_context;
	LassoIdWsf2DiscoEndpointContext *endpoint_context;

	/* Get metadatas ids to which the user is associated */
	svcMDIDs = lasso_identity_get_svc_md_ids(LASSO_PROFILE(login)->identity);
	/* Get the metadatas of type discovery to which the user is associated */
	svcMDs = lasso_server_get_svc_metadatas_with_id_and_type(LASSO_PROFILE(login)->server,
		svcMDIDs, LASSO_IDWSF2_DISCO_HREF);
	if (svcMDs == NULL) {
		/* If the user hasn't been associated to any discovery metadatas, */
		/* get a default one */
		svcMDs = lasso_server_get_svc_metadatas_with_id_and_type(
			LASSO_PROFILE(login)->server, NULL, LASSO_IDWSF2_DISCO_HREF);
		if (svcMDs != NULL && LASSO_IS_IDWSF2_DISCO_SVC_METADATA(svcMDs->data)) {
			/* Then associate the user to these metadatas for later use */
			lasso_identity_add_svc_md_id(LASSO_PROFILE(login)->identity,
				LASSO_IDWSF2_DISCO_SVC_METADATA(svcMDs->data)->svcMDID);
		} else {
			return;
		}
	}

	/* FIXME : foreach on the whole list and build on epr for each svcMD */
	svcMD = svcMDs->data;

	/* Check the metadatas contain the infos needed to build an EPR */
	if (svcMD == NULL || svcMD->ServiceContext == NULL || svcMD->ServiceContext->data == NULL) {
		g_list_foreach(svcMDs, (GFunc)lasso_node_destroy, NULL);
		g_list_free(svcMDs);
		return;
	}

	/* Build EndpointReference */

	epr = lasso_wsa_endpoint_reference_new();
	service_context = svcMD->ServiceContext->data;
	endpoint_context = service_context->EndpointContext->data;

	epr->Address = lasso_wsa_attributed_uri_new_with_string(
		(gchar*)endpoint_context->Address->data);

	metadata = lasso_wsa_metadata_new();

	/* Abstract */
	metadata->any = g_list_append(metadata->any,
			lasso_idwsf2_disco_abstract_new_with_string(svcMD->Abstract));
	/* ProviderID */
	metadata->any = g_list_append(metadata->any,
			lasso_idwsf2_disco_provider_id_new_with_string(svcMD->ProviderID));
	/* ServiceType */
	metadata->any = g_list_append(metadata->any,
			lasso_idwsf2_disco_service_type_new_with_string(
				(char*)service_context->ServiceType->data));
	/* Framework */
	if (endpoint_context->Framework != NULL) {
		metadata->any = g_list_append(metadata->any,
			g_object_ref(endpoint_context->Framework->data));
	}

	/* Identity token */
	assertion_identity_token = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());
	assertion_identity_token->Subject = g_object_ref(assertion->Subject);

	sec_token = lasso_idwsf2_sec_token_new();
	sec_token->any = LASSO_NODE(assertion_identity_token);

	security_context = lasso_idwsf2_disco_security_context_new();
	security_context->SecurityMechID = g_list_append(
		security_context->SecurityMechID, g_strdup(LASSO_SECURITY_MECH_TLS_BEARER));
	security_context->Token = g_list_append(security_context->Token, sec_token);

	metadata->any = g_list_append(metadata->any, security_context);

	/* End of metadata construction */
	epr->Metadata = metadata;

	/* Add the EPR to the assertion as a SAML attribute */
	attributeValue = lasso_saml2_attribute_value_new();
	attributeValue->any = g_list_append(attributeValue->any, epr);

	attribute = LASSO_SAML2_ATTRIBUTE(lasso_saml2_attribute_new());
	attribute->Name = g_strdup(LASSO_SAML2_ATTRIBUTE_NAME_EPR);
	attribute->NameFormat = g_strdup(LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI);
	attribute->AttributeValue = g_list_append(attribute->AttributeValue, attributeValue);

	attributeStatement = LASSO_SAML2_ATTRIBUTE_STATEMENT(lasso_saml2_attribute_statement_new());
	attributeStatement->Attribute = g_list_append(attributeStatement->Attribute, attribute);

	assertion->AttributeStatement = g_list_append(assertion->AttributeStatement,
		attributeStatement);

	/* Free resources */
	g_list_foreach(svcMDs, (GFunc)lasso_node_destroy, NULL);
	g_list_free(svcMDs);
}
#else
static void
lasso_saml20_login_assertion_add_discovery(G_GNUC_UNUSED LassoLogin *login, G_GNUC_UNUSED LassoSaml2Assertion *assertion)
{
}
#endif

int
lasso_saml20_login_build_assertion(LassoLogin *login,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *notBefore,
		const char *notOnOrAfter)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoFederation *federation;
	LassoSaml2Assertion *assertion;
	LassoSaml2AudienceRestriction *audience_restriction;
	LassoSamlp2NameIDPolicy *name_id_policy;
	LassoSaml2NameID *name_id = NULL;
	LassoSaml2AuthnStatement *authentication_statement;
	LassoProvider *provider = NULL;
	LassoSaml2EncryptedElement *encrypted_element = NULL;
	LassoSamlp2Response *response = NULL;
	LassoSamlp2RequestAbstract *request_abstract = NULL;

	provider = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);

	if (profile->request && LASSO_IS_SAMLP2_REQUEST_ABSTRACT(profile->request)) {
		request_abstract = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	}

	if (profile->identity && strcmp(login->nameIDPolicy,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) != 0) {
		char *name_id_sp_name_qualifier;
		if (provider->private_data->affiliation_id) {
			name_id_sp_name_qualifier = provider->private_data->affiliation_id;
		} else {
			name_id_sp_name_qualifier = profile->remote_providerID;
		}
		federation = g_hash_table_lookup(profile->identity->federations,
			name_id_sp_name_qualifier);
		if (federation == NULL) {
			message(G_LOG_LEVEL_WARNING, "can't find federation for identity");
		}
	} else {
		federation = NULL;
	}

	assertion = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());
	assertion->ID = lasso_build_unique_id(32);
	assertion->Version = g_strdup("2.0");
	assertion->IssueInstant = lasso_get_current_time();
	assertion->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	assertion->Conditions = LASSO_SAML2_CONDITIONS(lasso_saml2_conditions_new());

	audience_restriction = LASSO_SAML2_AUDIENCE_RESTRICTION(
			lasso_saml2_audience_restriction_new());
	audience_restriction->Audience = g_strdup(profile->remote_providerID);
	assertion->Conditions->AudienceRestriction = g_list_append(NULL, audience_restriction);

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	assertion->Subject = LASSO_SAML2_SUBJECT(lasso_saml2_subject_new());
	assertion->Subject->SubjectConfirmation = LASSO_SAML2_SUBJECT_CONFIRMATION(
			lasso_saml2_subject_confirmation_new());
	assertion->Subject->SubjectConfirmation->Method = g_strdup(
			LASSO_SAML2_CONFIRMATION_METHOD_BEARER);
	assertion->Subject->SubjectConfirmation->SubjectConfirmationData =
		LASSO_SAML2_SUBJECT_CONFIRMATION_DATA(
			lasso_saml2_subject_confirmation_data_new());
	assertion->Subject->SubjectConfirmation->SubjectConfirmationData->NotBefore = g_strdup(
		notBefore);
	assertion->Subject->SubjectConfirmation->SubjectConfirmationData->NotOnOrAfter = g_strdup(
		notOnOrAfter);
	if (request_abstract) {
		lasso_assign_string(assertion->Subject->SubjectConfirmation->SubjectConfirmationData->InResponseTo,
				request_abstract->ID);
		if (request_abstract->ID) {
			/**
			 * It MUST NOT contain a NotBefore attribute. If
			 * the containing message is in response to an <AuthnRequest>,
			 * then the InResponseTo attribute MUST match the request's ID.
			 */
			lasso_release_string(assertion->Subject->SubjectConfirmation->SubjectConfirmationData->NotBefore);
		}
	}

	if (name_id_policy && (strcmp(name_id_policy->Format,
			LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL) == 0 ||
			strcmp(name_id_policy->Format,
			LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED) == 0)) {
		/* caller must set the name identifier content afterwards */
		name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
		name_id->NameQualifier = g_strdup(
				LASSO_PROVIDER(profile->server)->ProviderID);
		name_id->Format = g_strdup(name_id_policy->Format);
		assertion->Subject->NameID = name_id;
	} else if (federation == NULL ||
			(name_id_policy && strcmp(name_id_policy->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) == 0)) {
		/* transient -> don't use a federation */
		name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
					lasso_build_unique_id(32)));
		name_id->NameQualifier = g_strdup(
				LASSO_PROVIDER(profile->server)->ProviderID);
		name_id->Format = g_strdup(LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);
		assertion->Subject->NameID = name_id;
	} else {
		if (provider && name_id_policy && strcmp(name_id_policy->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED) == 0) {
			provider->private_data->encryption_mode |= LASSO_ENCRYPTION_MODE_NAMEID;
		}
		if (federation->remote_nameIdentifier) {
			assertion->Subject->NameID = g_object_ref(
					federation->remote_nameIdentifier);
		} else {
			assertion->Subject->NameID = g_object_ref(
					federation->local_nameIdentifier);
		}
	}

	/* Encrypt NameID */
	if (provider && provider->private_data->encryption_mode & LASSO_ENCRYPTION_MODE_NAMEID
			&& provider->private_data->encryption_public_key != NULL
			&& assertion->Subject->NameID->content != NULL) {
		encrypted_element = LASSO_SAML2_ENCRYPTED_ELEMENT(lasso_node_encrypt(
			LASSO_NODE(assertion->Subject->NameID),
			provider->private_data->encryption_public_key,
			provider->private_data->encryption_sym_key_type));
		if (encrypted_element != NULL) {
			assertion->Subject->EncryptedID = encrypted_element;
			g_object_unref(assertion->Subject->NameID);
			assertion->Subject->NameID = NULL;
		}
	}

	authentication_statement = LASSO_SAML2_AUTHN_STATEMENT(lasso_saml2_authn_statement_new());
	authentication_statement->AuthnInstant = g_strdup(authenticationInstant);
	authentication_statement->SessionNotOnOrAfter = g_strdup(notOnOrAfter);
	authentication_statement->AuthnContext = LASSO_SAML2_AUTHN_CONTEXT(
			lasso_saml2_authn_context_new());
	authentication_statement->AuthnContext->AuthnContextClassRef = g_strdup(
			authenticationMethod);

	assertion->AuthnStatement = g_list_append(NULL, authentication_statement);

	/* Save signing material in assertion private datas to be able to sign later */
	if (profile->server->certificate) {
		assertion->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		assertion->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	assertion->sign_method = profile->server->signature_method;
	assertion->private_key_file = g_strdup(profile->server->private_key);
	assertion->private_key_password = g_strdup(profile->server->private_key_password);
	assertion->certificate_file = g_strdup(profile->server->certificate);

	/* Save encryption material in assertion private datas to be able to encrypt later */
	if (provider && provider->private_data->encryption_mode & LASSO_ENCRYPTION_MODE_ASSERTION
			&& provider->private_data->encryption_public_key != NULL) {
		assertion->encryption_activated = TRUE;
		assertion->encryption_public_key_str = g_strdup(
			provider->private_data->encryption_public_key_str);
		assertion->encryption_sym_key_type =
			provider->private_data->encryption_sym_key_type;
	}

	lasso_saml20_login_assertion_add_discovery(login, assertion);

	/* store assertion in session object */
	if (profile->session == NULL) {
		profile->session = lasso_session_new();
	}

	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_NODE(assertion));

	response = LASSO_SAMLP2_RESPONSE(profile->response);
	response->Assertion = g_list_append(NULL, assertion);

	login->private_data->saml2_assertion = g_object_ref(assertion);

	return 0;
}

gint
lasso_saml20_login_build_artifact_msg(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *artifact;
	char *url;
	LassoSaml2Assertion *assertion;
	LassoSamlp2StatusResponse *response;

	profile = LASSO_PROFILE(login);

	if (profile->remote_providerID == NULL)
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	url = lasso_saml20_login_get_assertion_consumer_service_url(login, remote_provider);
	assertion = login->private_data->saml2_assertion;
	if (LASSO_IS_SAML2_ASSERTION(assertion) == TRUE) {
		assertion->Subject->SubjectConfirmation->SubjectConfirmationData->Recipient =
			g_strdup(url);
	}

	artifact = lasso_saml20_profile_generate_artifact(profile, 1);
	login->assertionArtifact = g_strdup(artifact);
	if (http_method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
		gchar *query;
		char *url_artifact = (char*)xmlURIEscapeStr((xmlChar*)artifact, NULL);

		if (profile->msg_relayState) {
			query = g_strdup_printf("SAMLart=%s&RelayState=%s",
					url_artifact, profile->msg_relayState);
		} else {
			query = g_strdup_printf("SAMLart=%s", url_artifact);
		}
		profile->msg_url = lasso_concat_url_query(url, query);
		g_free(query);
		xmlFree(url_artifact);
	} else {
		/* XXX: ARTIFACT POST */
	}
	g_free(url);

	response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);
	if (response->Status == NULL || response->Status->StatusCode == NULL
			|| response->Status->StatusCode->Value == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	}

	if (strcmp(LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->Status->StatusCode->Value,
				"samlp:Success") != 0) {
		if (profile->session == NULL)
			profile->session = lasso_session_new();

		lasso_session_add_status(profile->session, profile->remote_providerID,
				g_object_ref(LASSO_SAMLP2_STATUS_RESPONSE(
						profile->response)->Status));
	} else {
		lasso_session_remove_status(profile->session, profile->remote_providerID);
	}

	return 0;
}


gint
lasso_saml20_login_init_request(LassoLogin *login, gchar *response_msg,
		LassoHttpMethod response_http_method)
{
	return lasso_saml20_profile_init_artifact_resolve(
			LASSO_PROFILE(login), response_msg, response_http_method);
}


gint
lasso_saml20_login_build_request_msg(LassoLogin *login)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	profile = LASSO_PROFILE(login);

	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_file =
		g_strdup(profile->server->private_key);
	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_password =
		g_strdup(profile->server->private_key_password);
	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->certificate_file =
		g_strdup(profile->server->certificate);
	profile->msg_body = lasso_node_export_to_soap(profile->request);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}
	profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
			"ArtifactResolutionService SOAP");
	return 0;
}

gint
lasso_saml20_login_process_request_msg(LassoLogin *login, gchar *request_msg)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	int rc;

	rc = lasso_saml20_profile_process_artifact_resolve(profile, request_msg);
	if (rc != 0) {
		return rc;
	}
	/* compat with liberty id-ff code */
	login->assertionArtifact = lasso_profile_get_artifact(profile);
	return 0;
}

gint
lasso_saml20_login_build_response_msg(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoProvider *remote_provider;
	LassoSaml2Assertion *assertion;

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP) {
		const char *assertionConsumerURL;

		if (profile->server->certificate) {
			LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_type =
				LASSO_SIGNATURE_TYPE_WITHX509;
		} else {
			LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_type =
				LASSO_SIGNATURE_TYPE_SIMPLE;
		}
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_method =
			LASSO_SIGNATURE_METHOD_RSA_SHA1;

		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->private_key_file =
			g_strdup(profile->server->private_key);
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->private_key_password =
			g_strdup(profile->server->private_key_password);
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->certificate_file =
			g_strdup(profile->server->certificate);

		remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
		if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
			return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

		assertionConsumerURL = lasso_saml20_login_get_assertion_consumer_service_url(
						login, remote_provider);

		assertion = login->private_data->saml2_assertion;
		if (LASSO_IS_SAML2_ASSERTION(assertion) == TRUE) {
			assertion->Subject->SubjectConfirmation->SubjectConfirmationData->Recipient
						= g_strdup(assertionConsumerURL);
		}

		/* build an ECP SOAP Response */
		profile->msg_body = lasso_node_export_to_ecp_soap_response(
					LASSO_NODE(profile->response), assertionConsumerURL);
		return 0;
	}

	return lasso_saml20_profile_build_artifact_response(LASSO_PROFILE(login));
}

gint
lasso_saml20_login_process_paos_response_msg(LassoLogin *login, gchar *msg)
{
	LassoProfile *profile;
	int rc1, rc2;

	lasso_bad_param(LOGIN, login);
	lasso_null_param(msg);

	profile = LASSO_PROFILE(login);
	rc1 = lasso_saml20_profile_process_soap_response(profile, msg);
	rc2 = lasso_saml20_login_process_response_status_and_assertion(login);

	if (rc1) {
		return rc1;
	}
	return rc2;
}

gint
lasso_saml20_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg)
{
	LassoProfile *profile = NULL;
	int rc1, rc2;

	lasso_bad_param(LOGIN, login);
	lasso_null_param(authn_response_msg);

	/* parse the message */
	profile = LASSO_PROFILE(login);
	rc1 = lasso_saml20_profile_process_any_response(profile,
		(LassoSamlp2StatusResponse*)lasso_samlp2_response_new(),
		authn_response_msg);

	rc2 = lasso_saml20_login_process_response_status_and_assertion(login);

	/** The more important signature errors */
	if (profile->signature_status) {
		return profile->signature_status;
	}
	if (rc1) {
		return rc1;
	}
	return rc2;
}

gint
lasso_saml20_login_process_response_msg(LassoLogin *login, gchar *response_msg)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	int rc;

	rc = lasso_saml20_profile_process_artifact_response(profile, response_msg);
	if (rc) {
		return rc;
	}

	return lasso_saml20_login_process_response_status_and_assertion(login);
}

static gint
lasso_saml20_login_process_response_status_and_assertion(LassoLogin *login)
{
	LassoSamlp2StatusResponse *response;
	LassoSamlp2Response *samlp2_response = NULL;
	LassoProfile *profile;
	xmlSecKey *encryption_private_key = NULL;
	char *status_value;
	GList *it = NULL;
	int rc = 0, rc1 = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);
	response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);
	lasso_extract_node_or_fail(response, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(samlp2_response, response, SAMLP2_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);

	if (response->Status == NULL || ! LASSO_IS_SAMLP2_STATUS(response->Status) ||
			response->Status->StatusCode == NULL ||
			response->Status->StatusCode->Value == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}

	status_value = response->Status->StatusCode->Value;
	if (status_value && strcmp(status_value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0) {
		if (strcmp(status_value, LASSO_SAML2_STATUS_CODE_REQUEST_DENIED) == 0)
			return LASSO_LOGIN_ERROR_REQUEST_DENIED;
		if (strcmp(status_value, LASSO_SAML2_STATUS_CODE_RESPONDER) == 0) {
			/* samlp:Responder */
			if (response->Status->StatusCode->StatusCode &&
					response->Status->StatusCode->StatusCode->Value) {
				status_value = response->Status->StatusCode->StatusCode->Value;
				if (strcmp(status_value,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST) == 0) {
					return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
				}
				if (strcmp(status_value,
						LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL) == 0) {
					return LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL;
				}
			}
		}

		return LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS;
	}


	if (LASSO_IS_SERVER(profile->server) && profile->server->private_data) {
		encryption_private_key = profile->server->private_data->encryption_private_key;
	}

	/* Decrypt all EncryptedAssertions */
	it = samlp2_response->EncryptedAssertion;
	for (;it;it = it->next) {
		LassoSaml2EncryptedElement *encrypted_assertion;
		LassoSaml2Assertion * assertion = NULL;

		if (! encryption_private_key) {
			message(G_LOG_LEVEL_WARNING, "Missing private encryption key, cannot decrypt assertions.");
			break;
		}

		if (! LASSO_IS_SAML2_ENCRYPTED_ELEMENT(it->data)) {
			message(G_LOG_LEVEL_WARNING, "EncryptedAssertion contains a non EncryptedElement object");
			continue;
		}
		encrypted_assertion = (LassoSaml2EncryptedElement*)it->data;
		rc1 = lasso_saml2_encrypted_element_decrypt(encrypted_assertion, encryption_private_key, (LassoNode**)&assertion);

		if (rc1) {
			message(G_LOG_LEVEL_WARNING, "Could not decrypt an assertion");
			continue;
		}

		if (! LASSO_IS_SAML2_ASSERTION(assertion)) {
			message(G_LOG_LEVEL_WARNING, "EncryptedAssertion contains something that is not an assertion");
			lasso_release_gobject(assertion);
			continue;
		}
		lasso_list_add_gobject(samlp2_response->Assertion, assertion);
		lasso_release_gobject(assertion);
	}

	/** FIXME: treat more than the first assertion ? */
	if (samlp2_response->Assertion != NULL) {
		LassoSaml2Subject *subject;
		LassoSaml2Assertion *assertion = samlp2_response->Assertion->data;
		int rc2 = 0;

		/* FIXME: verify assertion signature */

		if (! LASSO_IS_SAML2_SUBJECT(assertion->Subject)) {
			return LASSO_PROFILE_ERROR_MISSING_SUBJECT;
		}
		subject = assertion->Subject;

		/* Verify Subject->SubjectConfirmationData->InResponseTo */
		if (login->private_data->request_id && (
			assertion->Subject->SubjectConfirmation == NULL ||
			assertion->Subject->SubjectConfirmation->SubjectConfirmationData == NULL ||
			assertion->Subject->SubjectConfirmation->SubjectConfirmationData->InResponseTo == NULL ||
			strcmp(assertion->Subject->SubjectConfirmation->SubjectConfirmationData->InResponseTo, login->private_data->request_id) != 0)) {
			return LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID;
		}

		/** Handle nameid */
		rc2 = lasso_saml20_profile_process_name_identifier_decryption(profile, &subject->NameID, &subject->EncryptedID);

		if (rc2) {
			rc = rc2;
		}
	} else {
		if (rc1) {
			rc = rc1;
		} else {
			rc = LASSO_PROFILE_ERROR_MISSING_ASSERTION;
		}
	}

cleanup:

	return rc;
}

#ifdef LASSO_WSF_ENABLED
static gint
lasso_saml20_login_copy_assertion_epr(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSession *session = profile->session;
	LassoSaml2Assertion *assertion;
	LassoSaml2AttributeStatement *attribute_statement;
	LassoSaml2Attribute *attribute;
	LassoSaml2AttributeValue *attribute_value;
	LassoWsAddrEndpointReference *epr;
	GList *i;

	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);

	assertion = LASSO_SAML2_ASSERTION(
		LASSO_SAMLP2_RESPONSE(profile->response)->Assertion->data);

	for (i = g_list_first(assertion->AttributeStatement); i; i = g_list_next(i)) {
		GList *j;
		attribute_statement = LASSO_SAML2_ATTRIBUTE_STATEMENT(i->data);
		if (attribute_statement == NULL) {
			continue;
		}

		for (j = g_list_first(attribute_statement->Attribute); j; j = g_list_next(j)) {
			GList *k;
			attribute = LASSO_SAML2_ATTRIBUTE(j->data);
			if (attribute == NULL || attribute->Name == NULL) {
				continue;
			}
			if (strcmp(attribute->Name, LASSO_SAML2_ATTRIBUTE_NAME_EPR) != 0) {
				continue;
			}
			for (k = g_list_first(attribute->AttributeValue); k; k = g_list_next(k)) {
				GList *l;
				attribute_value = LASSO_SAML2_ATTRIBUTE_VALUE(k->data);
				if (attribute_value == NULL) {
					continue;
				}
				for (l = g_list_first(attribute_value->any);
						l; l = g_list_next(l)) {
					if (LASSO_IS_WSA_ENDPOINT_REFERENCE(l->data)) {
						epr = LASSO_WSA_ENDPOINT_REFERENCE(l->data);
						lasso_session_add_endpoint_reference(session, epr);
						return 0;
					}
				}
			}
		}
	}

	return 0;
}
#else
static gint
lasso_saml20_login_copy_assertion_epr(G_GNUC_UNUSED LassoLogin *login)
{
	return LASSO_ERROR_UNIMPLEMENTED;
}
#endif

gint
lasso_saml20_login_accept_sso(LassoLogin *login)
{
	LassoProfile *profile;
	LassoSaml2Assertion *assertion;
	GList *previous_assertions, *t;
	LassoSaml2NameID *ni, *idp_ni = NULL;
	LassoFederation *federation;

	profile = LASSO_PROFILE(login);
	if (LASSO_SAMLP2_RESPONSE(profile->response)->Assertion == NULL)
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;

	assertion = LASSO_SAMLP2_RESPONSE(profile->response)->Assertion->data;
	if (assertion == NULL)
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;

	previous_assertions = lasso_session_get_assertions(profile->session,
			profile->remote_providerID);
	for (t = previous_assertions; t; t = g_list_next(t)) {
		LassoSaml2Assertion *ta;

		if (LASSO_IS_SAML2_ASSERTION(t->data) == FALSE) {
			continue;
		}

		ta = t->data;

		if (strcmp(ta->ID, assertion->ID) == 0) {
			g_list_free(previous_assertions);
			return LASSO_LOGIN_ERROR_ASSERTION_REPLAY;
		}
	}
	g_list_free(previous_assertions);

	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_NODE(assertion));

	if (assertion->Subject && assertion->Subject->NameID) {
		ni = assertion->Subject->NameID;
	} else {
		return LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER;
	}

	/* create federation, only if nameidentifier format is Federated */
	if (strcmp(ni->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT) == 0) {
		federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
		if (ni != NULL && idp_ni != NULL) {
			federation->local_nameIdentifier = g_object_ref(ni);
			federation->remote_nameIdentifier = g_object_ref(idp_ni);
		} else {
			federation->remote_nameIdentifier = g_object_ref(ni);
		}
		/* add federation in identity */
		lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
	}

	lasso_saml20_login_copy_assertion_epr(login);

	return 0;
}

gint
lasso_saml20_login_build_authn_response_msg(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoProvider *remote_provider;
	LassoSaml2Assertion *assertion;

	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST &&
		login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	if (profile->server->certificate) {
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_type =
			LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_type =
			LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_method =
		LASSO_SIGNATURE_METHOD_RSA_SHA1;

	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->private_key_file =
		g_strdup(profile->server->private_key);
	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->private_key_password =
		g_strdup(profile->server->private_key_password);
	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->certificate_file =
		g_strdup(profile->server->certificate);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	profile->msg_url = lasso_saml20_login_get_assertion_consumer_service_url(
			login, remote_provider);
	if (profile->msg_url == NULL) {
		return LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL;
	}

	assertion = login->private_data->saml2_assertion;
	if (LASSO_IS_SAML2_ASSERTION(assertion) == TRUE) {
		assertion->Subject->SubjectConfirmation->SubjectConfirmationData->Recipient =
			g_strdup(profile->msg_url);
	}


	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		/* build an lib:AuthnResponse base64 encoded */
		profile->msg_body = lasso_node_export_to_base64(LASSO_NODE(profile->response));
	} else {
		int rc;
		char *url;

		url = profile->msg_url;
		rc = lasso_saml20_profile_build_http_redirect(profile, profile->response, 1, profile->msg_url);
		if (profile->msg_url != url) {
			lasso_release(url);
		}
		if (rc != 0) {
			return rc;
		}
	}


	return 0;

}

static char*
lasso_saml20_login_get_assertion_consumer_service_url(LassoLogin *login,
	LassoProvider *remote_provider)
{
	LassoSamlp2AuthnRequest *request;
	char *url = NULL;

	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);

	if (request->AssertionConsumerServiceURL) {
		return g_strdup(request->AssertionConsumerServiceURL);
	}

	if (request->AssertionConsumerServiceIndex != -1 || request->ProtocolBinding == NULL) {
		url = lasso_saml20_provider_get_assertion_consumer_service_url(remote_provider,
				request->AssertionConsumerServiceIndex);
	}

	if (url == NULL && request->ProtocolBinding) {
		url = lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(
				remote_provider, request->ProtocolBinding);
	}

	if (url == NULL) {
		message(G_LOG_LEVEL_WARNING,
				"can't find assertion consumer service url (going for default)");
		url = lasso_saml20_provider_get_assertion_consumer_service_url(remote_provider, -1);
	}

	return url;
}

gint
lasso_saml20_login_init_idp_initiated_authn_request(LassoLogin *login,
		const gchar *remote_providerID)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	int rc;

	rc = lasso_login_init_authn_request(login, remote_providerID, LASSO_HTTP_METHOD_POST);
	if (rc)
		return rc;

	g_free(LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID = NULL;

	g_free(LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Issuer->content);
	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Issuer->content =
		g_strdup(remote_providerID);

	return 0;
}


