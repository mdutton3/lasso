/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/saml-2.0/loginprivate.h>
#include <lasso/saml-2.0/profileprivate.h>
#include <lasso/saml-2.0/federationprivate.h>

#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/login.h>
#include <lasso/id-ff/identityprivate.h>
#include <lasso/id-ff/sessionprivate.h>
#include <lasso/id-ff/loginprivate.h>

#include <lasso/xml/saml-2.0/samlp2_authn_request.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <lasso/xml/saml-2.0/saml2_audience_restriction.h>


static int lasso_saml20_login_process_federation(LassoLogin *login, gboolean is_consent_obtained);
static gboolean lasso_saml20_login_must_ask_for_consent_private(LassoLogin *login);
static gint lasso_saml20_login_process_response_status_and_assertion(LassoLogin *login);

gint
lasso_saml20_login_init_authn_request(LassoLogin *login, LassoProvider *remote_provider,
		LassoHttpMethod http_method)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2RequestAbstract *request;

	if (http_method != LASSO_HTTP_METHOD_REDIRECT &&
			http_method != LASSO_HTTP_METHOD_POST &&
			http_method != LASSO_HTTP_METHOD_ARTIFACT_GET &&
			http_method != LASSO_HTTP_METHOD_ARTIFACT_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	login->http_method = http_method;
	/* XXX: check this protocol profile is supported */

	profile->request = lasso_samlp2_authn_request_new();
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	request->ID = lasso_build_unique_id(32);
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
	char *query, *url;
	char *md_authnRequestsSigned;
	gboolean must_sign;
	LassoProfile *profile = LASSO_PROFILE(login);

	md_authnRequestsSigned = lasso_provider_get_metadata_one(
			LASSO_PROVIDER(profile->server), "AuthnRequestsSigned");
	must_sign = (md_authnRequestsSigned && strcmp(md_authnRequestsSigned, "true") == 0);
	g_free(md_authnRequestsSigned);

	if (login->http_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* REDIRECT -> query */
		if (must_sign) {
			query = lasso_node_export_to_query(profile->request,
					profile->server->signature_method,
					profile->server->private_key);
		} else {
			query = lasso_node_export_to_query(
					LASSO_NODE(profile->request), 0, NULL);
		}
		if (query == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}

		url = lasso_provider_get_metadata_one(remote_provider,
				"SingleSignOnService HTTP-Redirect");
		if (url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}

		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		profile->msg_body = NULL;
		g_free(query);
		g_free(url);
	} else {
		/* POST and Artifact-GET|POST */
		if (must_sign) {
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_file = 
				g_strdup(profile->server->private_key);
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->certificate_file = 
				g_strdup(profile->server->certificate);
		}

		if (login->http_method == LASSO_HTTP_METHOD_POST) {
			char *lareq = lasso_node_export_to_base64(profile->request);
			profile->msg_url = lasso_provider_get_metadata_one(
					remote_provider, "SingleSignOnService HTTP-POST");
			profile->msg_body = lareq;
		} else {
			/* artifact method */
			char *artifact = lasso_saml20_profile_generate_artifact(profile, 0);
			url = lasso_provider_get_metadata_one(
					remote_provider, "SingleSignOnService HTTP-Artifact");
			if (login->http_method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
				profile->msg_url = g_strdup_printf("%s?SAMLArt=%s",
						url, artifact);
			} else {
				/* TODO: ARTIFACT POST */
			}
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
	gchar *protocol_binding;

	request = lasso_samlp2_authn_request_new();
	format = lasso_node_init_from_message(request, authn_request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN ||
			format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	profile->request = request;
	profile->remote_providerID = g_strdup(
			LASSO_SAMLP2_REQUEST_ABSTRACT(request)->Issuer->content);

	protocol_binding = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->ProtocolBinding;
	if (protocol_binding == NULL) {
		/* protocol binding not set; will look into
		 * AssertionConsumingServiceIndex */
		int service_index = LASSO_SAMLP2_AUTHN_REQUEST(
				profile->request)->AssertionConsumerServiceIndex;
		if (service_index == -1) {
			/* XXX: what does spec say when protocol binding and
			 * attribute consuming service index are both unset ?
			 */
			message(G_LOG_LEVEL_WARNING, "missing service index");
		} else {
			gchar *binding;
			LassoProvider *remote_provider;

			remote_provider = g_hash_table_lookup(profile->server->providers,
					profile->remote_providerID);

			binding = lasso_saml20_provider_get_assertion_consumer_service_binding(
					remote_provider, service_index);
			if (binding == NULL) {
				message(G_LOG_LEVEL_WARNING, "can't find binding for index");
			} else if (strcmp(binding, "HTTP-Artifact") == 0) {
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
			} else if (strcmp(binding, "HTTP-POST") == 0) {
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
			}
		}
	} else if (strcmp(protocol_binding, LASSO_SAML20_METADATA_BINDING_ARTIFACT) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
	} else if (strcmp(protocol_binding, LASSO_SAML20_METADATA_BINDING_POST) == 0) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
	} else {
		/* XXX: are there other protocols to handle ? */
		message(G_LOG_LEVEL_WARNING,
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

	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
	if (request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
	}

	/* get IsPassive and ForceAuthn in AuthnRequest if exists */
	if ((request->ForceAuthn || LASSO_PROFILE(login)->session == NULL) &&
			request->IsPassive == FALSE)
		return TRUE;

	return FALSE;
}

static gboolean
lasso_saml20_login_must_ask_for_consent_private(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2NameIDPolicy *name_id_policy;
	char *consent;

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;

	if (name_id_policy) {
		char *format = name_id_policy->Format;
		if (strcmp(format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) == 0) {
			return FALSE;
		}
	}

	consent = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Consent;
	if (consent == NULL)
		return TRUE;

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
	int ret;

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
		if (ret)
			return ret;
	}

	lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_SUCCESS);

	return 0;
}

static int
lasso_saml20_login_process_federation(LassoLogin *login, gboolean is_consent_obtained)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2NameIDPolicy *name_id_policy;
	char *name_id_policy_format = NULL;
	LassoFederation *federation;

	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	if (name_id_policy)
		name_id_policy_format = name_id_policy->Format;
	else
		return 0; /* XXX: ? */

	if (name_id_policy_format && strcmp(name_id_policy_format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) == 0) {
		return 0;
	}

	/* search a federation in the identity */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (name_id_policy->AllowCreate == FALSE) {
		/* a federation MUST exist */
		if (federation == NULL) {
			return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
		}
	}

	if (lasso_saml20_login_must_ask_for_consent_private(login) && !is_consent_obtained) {
		return LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
	}

	if (federation == NULL) {
		federation = lasso_federation_new(profile->remote_providerID);
		lasso_saml20_federation_build_local_name_identifier(federation,
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,
				NULL);
		lasso_identity_add_federation(profile->identity, federation);
	}

	profile->nameIdentifier = g_object_ref(federation->local_nameIdentifier);

	return 0;
}

int
lasso_saml20_login_build_assertion(LassoLogin *login,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoFederation *federation;
	LassoSaml2Assertion *assertion;
	LassoSaml2AudienceRestriction *audience_restriction;
	LassoSamlp2NameIDPolicy *name_id_policy;
	LassoSaml2NameID *name_id = NULL;

	federation = g_hash_table_lookup(profile->identity->federations,
			                        profile->remote_providerID);

	assertion = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());
	assertion->ID = lasso_build_unique_id(32);
	assertion->Version = g_strdup("2.0");
	assertion->IssueInstant = lasso_get_current_time();
	assertion->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	assertion->Conditions = LASSO_SAML2_CONDITIONS(lasso_saml2_conditions_new());
	assertion->Conditions->NotBefore = g_strdup(notBefore);
	assertion->Conditions->NotOnOrAfter = g_strdup(notOnOrAfter);
	audience_restriction = LASSO_SAML2_AUDIENCE_RESTRICTION(
			lasso_saml2_audience_restriction_new());
	audience_restriction->Audience = g_strdup(profile->remote_providerID);
	assertion->Conditions->AudienceRestriction = g_list_append(NULL, audience_restriction);

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	assertion->Subject = LASSO_SAML2_SUBJECT(lasso_saml2_subject_new());
	if (name_id_policy == NULL || strcmp(name_id_policy->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) == 0) {
		/* transient -> don't use a federation */
		name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
					lasso_build_unique_id(32)));
		name_id->NameQualifier = g_strdup(
				LASSO_PROVIDER(profile->server)->ProviderID);
		name_id->Format = g_strdup(LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);

		assertion->Subject->NameID = name_id;
	} else {
		if (federation->remote_nameIdentifier) {
			assertion->Subject->NameID = g_object_ref(
					federation->remote_nameIdentifier);
		} else {
			assertion->Subject->NameID = g_object_ref(
					federation->local_nameIdentifier);
		}
	}

	if (profile->server->certificate) {
		assertion->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		assertion->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	assertion->sign_method = profile->server->signature_method;
	assertion->private_key_file = g_strdup(profile->server->private_key);
	assertion->certificate_file = g_strdup(profile->server->certificate);

	/* store assertion in session object */
	if (profile->session == NULL) {
		profile->session = lasso_session_new();
	}

	lasso_session_add_assertion(profile->session,
			profile->remote_providerID,
			g_object_ref(assertion));

	LASSO_SAMLP2_RESPONSE(profile->response)->Assertion = g_list_append(NULL, assertion);

	return 0;
}


gint
lasso_saml20_login_build_artifact_msg(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *artifact;
	char *url;

	profile = LASSO_PROFILE(login);

	if (profile->remote_providerID == NULL)
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	url = lasso_saml20_provider_get_assertion_consumer_service_url(remote_provider,
			LASSO_SAMLP2_AUTHN_REQUEST(
				profile->request)->AssertionConsumerServiceIndex);

	artifact = lasso_saml20_profile_generate_artifact(profile, 1);
	login->assertionArtifact = g_strdup(artifact);
	if (http_method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
		profile->msg_url = g_strdup_printf("%s?SAMLArt=%s", url, artifact);
		/* XXX: RelayState */
	} else {
		/* XXX: ARTIFACT POST */
	}
	g_free(url);
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
	profile->msg_body = lasso_node_export_to_soap(profile->request);

	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_file =
		g_strdup(profile->server->private_key);
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
lasso_saml20_login_build_response_msg(LassoLogin *login, gchar *remote_providerID)
{
	return lasso_saml20_profile_build_artifact_response(LASSO_PROFILE(login));
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
	LassoProvider *idp;
	LassoSamlp2StatusResponse *response;
	char *status_value;
	int ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	response = LASSO_SAMLP2_STATUS_RESPONSE(LASSO_PROFILE(login)->response);

	if (response->Status == NULL || ! LASSO_IS_SAMLP2_STATUS(response->Status) || 
			response->Status->StatusCode == NULL ||
			response->Status->StatusCode->Value == NULL) {
		return LASSO_ERROR_UNDEFINED;
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

	if (LASSO_SAMLP2_RESPONSE(response)->Assertion) {
		LassoProfile *profile = LASSO_PROFILE(login);
		LassoSaml2Assertion *assertion = LASSO_SAMLP2_RESPONSE(response)->Assertion->data;
		idp = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
		if (idp == NULL)
			return LASSO_ERROR_UNDEFINED;

		/* FIXME: verify assertion signature */

		/* store NameIdentifier */
		if (assertion->Subject == NULL) {
			return LASSO_ERROR_UNDEFINED;
		}

		profile->nameIdentifier = g_object_ref(assertion->Subject->NameID);

		if (LASSO_PROFILE(login)->nameIdentifier == NULL)
			return LASSO_ERROR_UNDEFINED;
	}

	return ret;
}

gint
lasso_saml20_login_accept_sso(LassoLogin *login)
{
	LassoProfile *profile;
	LassoSaml2Assertion *assertion;
	LassoSaml2NameID *ni, *idp_ni = NULL;
	LassoFederation *federation;

	profile = LASSO_PROFILE(login);

	if (LASSO_SAMLP2_RESPONSE(profile->response)->Assertion == NULL)
		return LASSO_ERROR_UNDEFINED;

	assertion = LASSO_SAMLP2_RESPONSE(profile->response)->Assertion->data;
	if (assertion == NULL)
		return LASSO_ERROR_UNDEFINED;

	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			g_object_ref(assertion));

	ni = assertion->Subject->NameID;

	if (ni == NULL)
		return LASSO_ERROR_UNDEFINED;


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

	return 0;
}

gint
lasso_saml20_login_build_authn_response_msg(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoProvider *remote_provider;

	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	if (login->private_data->saml2_assertion) {
		LassoSaml2Assertion *assertion = login->private_data->saml2_assertion;
		/* XXX ?*/
	}

	if (profile->server->certificate)
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_type =
			LASSO_SIGNATURE_TYPE_WITHX509;
	else
		LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_type =
			LASSO_SIGNATURE_TYPE_SIMPLE;
	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->sign_method =
		LASSO_SIGNATURE_METHOD_RSA_SHA1;

	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->private_key_file = 
		g_strdup(profile->server->private_key);
	LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->certificate_file = 
		g_strdup(profile->server->certificate);

	/* build an lib:AuthnResponse base64 encoded */
	profile->msg_body = lasso_node_export_to_base64(LASSO_NODE(profile->response));

	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	profile->msg_url = lasso_saml20_provider_get_assertion_consumer_service_url(
			remote_provider,
			LASSO_SAMLP2_AUTHN_REQUEST(
				profile->request)->AssertionConsumerServiceIndex);


	return 0;

}

