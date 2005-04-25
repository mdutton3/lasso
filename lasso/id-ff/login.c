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

#include <xmlsec/base64.h>

#include <lasso/lasso_config.h>
#include <lasso/xml/lib_authentication_statement.h>
#include <lasso/xml/lib_subject.h>
#include <lasso/xml/saml_advice.h>
#include <lasso/xml/saml_attribute.h>
#include <lasso/xml/saml_attribute_value.h>
#include <lasso/xml/samlp_response.h>

#ifdef LASSO_WSF_ENABLED
#include <lasso/xml/disco_description.h>
#include <lasso/xml/disco_resource_offering.h>
#include <lasso/xml/disco_service_instance.h>
#endif

#include <lasso/id-ff/login.h>
#include <lasso/id-ff/provider.h>

#include <lasso/id-ff/profileprivate.h>
#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/serverprivate.h>
#include <lasso/id-ff/sessionprivate.h>
#include <lasso/id-ff/identityprivate.h>

struct _LassoLoginPrivate
{
	char *soap_request_msg;
#ifdef LASSO_WSF_ENABLED
	LassoDiscoResourceID *resourceId;
	LassoDiscoEncryptedResourceID *encryptedResourceId;
#endif
};


static void lasso_login_assertion_add_discovery(LassoLogin *login, LassoSamlAssertion *assertion);
static void lasso_login_build_assertion_artifact(LassoLogin *login);

/*****************************************************************************/
/* static methods/functions */
/*****************************************************************************/


/**
 * lasso_login_assertion_add_discovery:
 * @login: a #LassoLogin
 * @assertion:
 *
 * Adds AttributeStatement and ResourceOffering attributes to assertion if
 * there is a discovery service.
 **/
static void
lasso_login_assertion_add_discovery(LassoLogin *login, LassoSamlAssertion *assertion)
{
#ifdef LASSO_WSF_ENABLED
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoDiscoResourceOffering *resourceOffering;
	LassoDiscoServiceInstance *serviceInstance, *newServiceInstance;
	LassoSamlAttributeStatement *attributeStatement;
	LassoSamlAttribute *attribute;
	LassoSamlAttributeValue *attributeValue;

	LassoSamlAssertion *credential;
	LassoSamlAdvice *advice;
	GList *listDescriptions, *listSecurityMechIds;
	LassoDiscoDescription *description;
	gchar *securityMechId;
	gboolean found;

	serviceInstance = lasso_server_get_service(profile->server, LASSO_DISCO_HREF);
	if (LASSO_IS_DISCO_SERVICE_INSTANCE(serviceInstance)) {
		newServiceInstance = lasso_disco_service_instance_copy(serviceInstance);

		resourceOffering = lasso_disco_resource_offering_new(newServiceInstance);
		resourceOffering->ResourceID = g_object_ref(login->private_data->resourceId);

		attributeValue = lasso_saml_attribute_value_new();
		attributeValue->any = g_list_append(attributeValue->any, resourceOffering);

		attribute = lasso_saml_attribute_new();
		attribute->attributeName = "DiscoveryResourceOffering";
		attribute->attributeNameSpace = g_strdup(LASSO_DISCO_HREF);
		attribute->AttributeValue = g_list_append(attribute->AttributeValue,
				attributeValue);

		attributeStatement = lasso_saml_attribute_statement_new();
		attributeStatement->Attribute = g_list_append(
				attributeStatement->Attribute, attribute);

		assertion->AttributeStatement = attributeStatement;

		/* Add optional credential */
		listDescriptions = newServiceInstance->Description;
		while (listDescriptions) {
			description = LASSO_DISCO_DESCRIPTION(listDescriptions->data);
			listSecurityMechIds = description->SecurityMechID;
			found = FALSE;
			while(listSecurityMechIds) {
				securityMechId = listSecurityMechIds->data;
				if (g_str_equal(securityMechId,
						LASSO_SECURITY_MECH_SAML)==TRUE || \
				    g_str_equal(securityMechId,
						LASSO_SECURITY_MECH_TLS_SAML) == TRUE || \
				    g_str_equal(securityMechId,
						LASSO_SECURITY_MECH_CLIENT_TLS_SAML)==TRUE) {
					found  = TRUE;
					break;
			  }
			  
			  listSecurityMechIds = listSecurityMechIds->next;
			}
			if (found == TRUE) {
				/* FIXME: Add required attributes for assertion */
				credential = lasso_saml_assertion_new();
				credential->AssertionID = lasso_build_unique_id(32);
				credential->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
				credential->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
				assertion->IssueInstant = lasso_get_current_time();

				advice = LASSO_SAML_ADVICE(lasso_saml_advice_new());
				advice->Assertion = LASSO_NODE(credential);
				assertion->Advice = advice;

				description->CredentialRef = g_list_append(
					description->CredentialRef,
					g_strdup(credential->AssertionID));
			}

			listDescriptions = listDescriptions->next;
		}
	}
#endif
}


/**
 * lasso_login_build_assertion:
 * @login: a #LassoLogin
 * @authenticationMethod: the authentication method
 * @authenticationInstant: the time at which the authentication took place
 * @reauthenticateOnOrAfter: the time at, or after which the service provider
 *     must reauthenticates the principal with the identity provider
 * @notBefore: the earliest time instant at which the assertion is valid
 * @notOnOrAfter: the time instant at which the assertion has expired
 * 
 * Builds an assertion and stores it in profile session.
 * @authenticationInstant, reauthenticateOnOrAfter, @notBefore and
 * @notOnOrAfter may be NULL.  If @authenticationInstant is NULL, the current
 * time will be used.  Time values must be encoded in UTC.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_login_build_assertion(LassoLogin *login,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter)
{
	LassoSamlAssertion *assertion;
	LassoLibAuthenticationStatement *as;
	LassoSamlNameIdentifier *nameIdentifier = NULL;
	LassoProfile *profile;
	LassoFederation *federation;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	/* federation MAY be NULL */

	profile = LASSO_PROFILE(login);

	if (profile->identity == NULL)
		return LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND;

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	
	assertion = LASSO_SAML_ASSERTION(lasso_lib_assertion_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			profile->request->RequestID,
			profile->remote_providerID, notBefore, notOnOrAfter));

	if (strcmp(login->nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0) {
		/* if NameIDPolicy is 'onetime', don't use a federation */
		nameIdentifier = lasso_saml_name_identifier_new();
		nameIdentifier->content = lasso_build_unique_id(32);
		nameIdentifier->NameQualifier = g_strdup(
				LASSO_PROVIDER(profile->server)->ProviderID);
		nameIdentifier->Format = g_strdup(LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME);

		as = lasso_lib_authentication_statement_new_full(authenticationMethod,
				authenticationInstant, reauthenticateOnOrAfter,
				NULL, nameIdentifier);
		profile->nameIdentifier = nameIdentifier;
	} else {
		as = lasso_lib_authentication_statement_new_full(authenticationMethod,
				authenticationInstant, reauthenticateOnOrAfter,
				federation->remote_nameIdentifier,
				federation->local_nameIdentifier);
	}

	assertion->AuthenticationStatement = LASSO_SAML_AUTHENTICATION_STATEMENT(as);

	if (profile->server->certificate) {
		assertion->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		assertion->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	assertion->sign_method = profile->server->signature_method;
	assertion->private_key_file = g_strdup(profile->server->private_key);
	assertion->certificate_file = g_strdup(profile->server->certificate);

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		/* only add assertion if response is an AuthnResponse */
		LASSO_SAMLP_RESPONSE(profile->response)->Assertion = g_list_append(NULL, assertion);
	}

	lasso_login_assertion_add_discovery(login, assertion);

	/* store assertion in session object */
	if (profile->session == NULL) {
		profile->session = lasso_session_new();
	}
	if (login->assertion)
		lasso_node_destroy(LASSO_NODE(login->assertion));
	login->assertion = LASSO_SAML_ASSERTION(g_object_ref(assertion));
	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_SAML_ASSERTION(g_object_ref(assertion)));

	if (profile->request->MajorVersion == 1 && profile->request->MinorVersion < 2) {
		/* pre-id-ff 1.2, saml 1.0 */
		LassoSamlSubjectStatementAbstract *ss;

		/* needs assertion artifact */
		lasso_login_build_assertion_artifact(login);

		assertion->MinorVersion = 0;

		ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement);
		ss->Subject = LASSO_SAML_SUBJECT(lasso_saml_subject_new());
		ss->Subject->NameIdentifier = g_object_ref(profile->nameIdentifier);
		ss->Subject->SubjectConfirmation = lasso_saml_subject_confirmation_new();
		if (ss->Subject->SubjectConfirmation->ConfirmationMethod) {
			/* we know it will only have one element */
			g_free(ss->Subject->SubjectConfirmation->ConfirmationMethod->data);
			g_list_free(ss->Subject->SubjectConfirmation->ConfirmationMethod);
		}
		/* liberty-architecture-bindings-profiles-v1.1.pdf, page 24, line 729 */
		ss->Subject->SubjectConfirmation->ConfirmationMethod = g_list_append(NULL,
				g_strdup(LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01));
		ss->Subject->SubjectConfirmation->SubjectConfirmationData = 
			g_strdup(login->assertionArtifact);

		if (nameIdentifier) {
			/* draft-liberty-idff-protocols-schemas-1.2-errata-v2.0.pdf */
			g_free(nameIdentifier->NameQualifier);
			nameIdentifier->NameQualifier = NULL;
			g_free(nameIdentifier->Format);
			nameIdentifier->Format = NULL;
		}
	}
	
	return 0;
}

/**
 * lasso_login_must_ask_for_consent_private:
 * @login: a #LassoLogin
 * 
 * Evaluates if it is necessary to ask the consent of the Principal. 
 * This method doesn't take the isPassive value into account.
 * 
 * Return value: TRUE or FALSE
 **/
static gboolean
lasso_login_must_ask_for_consent_private(LassoLogin *login)
{
	xmlChar *nameIDPolicy, *consent;
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoFederation *federation = NULL;

	nameIDPolicy = LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy;

	if (nameIDPolicy == NULL || strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_NONE) == 0)
		return FALSE;

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0)
		return FALSE;

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED) != 0 &&
			strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "Unknown NameIDPolicy: %s", nameIDPolicy);
		/* NameIDPolicy is considered empty (None value) if its value is unknown/invalid */
		return TRUE;
	}

	if (profile->identity != NULL) {
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (federation)
			return FALSE;
	}

	consent = LASSO_LIB_AUTHN_REQUEST(profile->request)->consent;
	if (consent == NULL)
		return TRUE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED_PRIOR) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED_CURRENT_IMPLICIT) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED_CURRENT_EXPLICIT) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_UNAVAILABLE) == 0)
		return TRUE;

	if (strcmp(consent, LASSO_LIB_CONSENT_INAPPLICABLE) == 0)
		return TRUE;

	message(G_LOG_LEVEL_CRITICAL, "Unknown consent value: %s", consent);
	/* we consider consent as empty if its value is unknown/invalid */
	return TRUE;
}

/**
 * lasso_login_process_federation:
 * @login: a #LassoLogin
 * @is_consent_obtained: whether user consent has been obtained
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
static gint
lasso_login_process_federation(LassoLogin *login, gboolean is_consent_obtained)
{
	LassoFederation *federation = NULL;
	LassoProfile *profile = LASSO_PROFILE(login);
	char *nameIDPolicy;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}

	/* get nameIDPolicy in lib:AuthnRequest */
	nameIDPolicy = LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	if (nameIDPolicy == NULL)
		nameIDPolicy = LASSO_LIB_NAMEID_POLICY_TYPE_NONE;
	login->nameIDPolicy = g_strdup(nameIDPolicy);

	/* if nameIDPolicy is 'onetime' => nothing to do */
	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0) {
		return 0;
	}

	/* search a federation in the identity */
	federation = g_hash_table_lookup(LASSO_PROFILE(login)->identity->federations,
			LASSO_PROFILE(login)->remote_providerID);

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_NONE) == 0) {
		/* a federation MUST exist */
		if (federation == NULL) {
			/* if protocolProfile is LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST
			 * set StatusCode to FederationDoesNotExist in lib:AuthnResponse
			 */
			lasso_profile_set_response_status(LASSO_PROFILE(login),
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
		}

		LASSO_PROFILE(login)->nameIdentifier = g_object_ref(
			LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));
		return 0;
	}

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED) != 0 &&
			strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0) {
		return critical_error(LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY);
	}

	/* consent is necessary, it should be obtained via consent attribute
	 * in lib:AuthnRequest or IDP should ask the Principal
	 */
	if (lasso_login_must_ask_for_consent_private(login) && !is_consent_obtained) {
		if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) == 0) {
			/* if the NameIDPolicy element is 'any' and if the policy
			 * for the Principal forbids federation, then evaluation
			 * MAY proceed as if the value was 'onetime'.
			 */
			g_free(login->nameIDPolicy);
			login->nameIDPolicy = g_strdup(LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME);
			return 0;
		}
		
		/* if protocolProfile is LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST
		 * set StatusCode to FederationDoesNotExist in lib:AuthnResponse
		 */
		/* FIXME : is it the correct value for the StatusCode ? */
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
	}

	if (federation == NULL) {
		federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
		lasso_federation_build_local_name_identifier(federation,
				LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID,
				LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED,
				NULL);
		lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
	}

	LASSO_PROFILE(login)->nameIdentifier = 
		g_object_ref(LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));

	return ret;
}

static gint
lasso_login_process_response_status_and_assertion(LassoLogin *login)
{
	LassoProvider *idp;
	LassoSamlpResponse *response;
	char *status_value;
	int ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	response = LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response);

	if (response->Status == NULL || ! LASSO_IS_SAMLP_STATUS(response->Status) || 
			response->Status->StatusCode == NULL ||
			response->Status->StatusCode->Value == NULL) {
		return LASSO_ERROR_UNDEFINED;
	}

	status_value = response->Status->StatusCode->Value;
	if (status_value && strcmp(status_value, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		if (strcmp(status_value, LASSO_SAML_STATUS_CODE_REQUEST_DENIED) == 0)
			return LASSO_LOGIN_ERROR_REQUEST_DENIED;
		if (strcmp(status_value, LASSO_SAML_STATUS_CODE_RESPONDER) == 0) {
			/* samlp:Responder */
			if (response->Status->StatusCode->StatusCode &&
					response->Status->StatusCode->StatusCode->Value) {
				status_value = response->Status->StatusCode->StatusCode->Value;
				if (strcmp(status_value,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST) == 0) {
					return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
				}
			}
		}
		return LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS;
	}

	if (response->Assertion) {
		LassoProfile *profile = LASSO_PROFILE(login);
		LassoSamlAssertion *assertion = response->Assertion->data;
		idp = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
		if (idp == NULL)
			return LASSO_ERROR_UNDEFINED;

		/* FIXME: verify assertion signature */

		/* store NameIdentifier */
		if (assertion->AuthenticationStatement == NULL) {
			return LASSO_ERROR_UNDEFINED;
		}

		profile->nameIdentifier = g_object_ref(
				LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
					assertion->AuthenticationStatement
					)->Subject->NameIdentifier);

		if (LASSO_PROFILE(login)->nameIdentifier == NULL)
			return LASSO_ERROR_UNDEFINED;
	}

	return ret;
}

/*****************************************************************************/
/* public methods */
/*****************************************************************************/

/**
 * lasso_login_accept_sso:
 * @login: a #LassoLogin
 * 
 * Gets the assertion of the response and adds it into the session.
 * Builds a federation with the 2 name identifiers of the assertion
 * and adds it into the identity.
 * If the session or the identity are NULL, they are created.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_accept_sso(LassoLogin *login)
{
	LassoProfile *profile;
	LassoSamlAssertion *assertion;
	LassoSamlNameIdentifier *ni, *idp_ni = NULL;
	LassoFederation *federation;
	LassoSamlSubjectStatementAbstract *authentication_statement;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	if (profile->identity == NULL)
		profile->identity = lasso_identity_new(); 

	if (profile->session == NULL)
		profile->session = lasso_session_new();

	if (profile->response == NULL)
		return LASSO_ERROR_UNDEFINED;

	if (LASSO_SAMLP_RESPONSE(profile->response)->Assertion == NULL)
		return LASSO_ERROR_UNDEFINED;

	assertion = LASSO_SAMLP_RESPONSE(profile->response)->Assertion->data;
	if (assertion == NULL)
		return LASSO_ERROR_UNDEFINED;

	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			g_object_ref(assertion));

	authentication_statement = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
			assertion->AuthenticationStatement);
	ni = authentication_statement->Subject->NameIdentifier;

	if (ni == NULL)
		return LASSO_ERROR_UNDEFINED;

	if (LASSO_IS_LIB_SUBJECT(authentication_statement->Subject)) {
		idp_ni = LASSO_LIB_SUBJECT(
				authentication_statement->Subject)->IDPProvidedNameIdentifier;
	}

	/* create federation, only if nameidentifier format is Federated */
	if (strcmp(ni->Format, LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED) == 0) {
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

static void
lasso_login_build_assertion_artifact(LassoLogin *login)
{
	xmlSecByte samlArt[42], *b64_samlArt;
	xmlChar *identityProviderSuccinctID;

	identityProviderSuccinctID = lasso_sha1(
			LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID);

	/* Artifact Format is described in "Binding Profiles", 3.2.2.2. */
	memcpy(samlArt, "\000\003", 2); /* type code */
	memcpy(samlArt+2, identityProviderSuccinctID, 20);
	lasso_build_random_sequence(samlArt+22, 20);

	xmlFree(identityProviderSuccinctID);
	b64_samlArt = xmlSecBase64Encode(samlArt, 42, 0);

	login->assertionArtifact = g_strdup(b64_samlArt);
	xmlFree(b64_samlArt);
}

/**
 * lasso_login_build_artifact_msg:
 * @login: a #LassoLogin
 * @http_method: the HTTP method to send the artifact (REDIRECT or POST)
 * 
 * Builds a SAML artifact. Depending of the HTTP method, the data for the sending of
 * the artifact are stored in @msg_url (REDIRECT) or @msg_url, @msg_body and
 * @msg_relayState (POST).
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_build_artifact_msg(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProvider *remote_provider;
	LassoProfile *profile;
	gchar *url;
	xmlSecByte *b64_samlArt, *relayState;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (http_method != LASSO_HTTP_METHOD_REDIRECT && http_method != LASSO_HTTP_METHOD_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	profile = LASSO_PROFILE(login);

	/* ProtocolProfile must be BrwsArt */
	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	if (profile->remote_providerID == NULL)
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);

	/* build artifact infos */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	url = lasso_provider_get_assertion_consumer_service_url(remote_provider,
			LASSO_LIB_AUTHN_REQUEST(profile->request)->AssertionConsumerServiceID);
	if (url == NULL) {
		/* from draft-liberty-idff-protocols-schema-1.2-errata-v2.0.pdf
		 * paragraph starting line 768,
		 *
		 * If the <AssertionConsumerServiceID> element is provided,
		 * then the identity provider MUST search for the value among
		 * the id attributes in the <AssertionConsumerServiceURL>
		 * elements in the provider's metadata to determine the URL
		 * to use. If no match can be found, then the provider MUST
		 * return an error with a second-level <samlp:StatusCode> of
		 * lib:InvalidAssertionConsumerServiceIndex to the default URL
		 */
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_INVALID_ASSERTION_CONSUMER_SERVICE_INDEX);
		url = lasso_provider_get_assertion_consumer_service_url(
				remote_provider, NULL);
	}

	/* it may have been created in lasso_login_build_assertion */
	if (login->assertionArtifact == NULL)
		lasso_login_build_assertion_artifact(login);

	if (login->assertion) {
		LassoSamlAssertion *assertion = login->assertion;
		LassoSamlSubjectStatementAbstract *ss;

		ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement);
		if (assertion->MajorVersion == 1 && assertion->MinorVersion == 0) {
			ss->Subject->SubjectConfirmation->ConfirmationMethod = g_list_append(NULL,
					g_strdup(LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01));
		} else {
			ss->Subject->SubjectConfirmation->ConfirmationMethod = g_list_append(NULL,
					g_strdup(LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT));
		}
	}

	b64_samlArt = xmlStrdup(login->assertionArtifact);
	relayState = xmlURIEscapeStr(LASSO_LIB_AUTHN_REQUEST(profile->request)->RelayState, NULL);

	if (http_method == LASSO_HTTP_METHOD_REDIRECT) {
		xmlChar *escaped_artifact = xmlURIEscapeStr(b64_samlArt, NULL);
		if (relayState == NULL) {
			profile->msg_url = g_strdup_printf("%s?SAMLart=%s", url, escaped_artifact);
		} else {
			profile->msg_url = g_strdup_printf(
					"%s?SAMLart=%s&RelayState=%s", 
					url, escaped_artifact, relayState);
		}
		xmlFree(escaped_artifact);
	}

	if (http_method == LASSO_HTTP_METHOD_POST) {
		profile->msg_url = g_strdup(url);
		profile->msg_body = g_strdup(b64_samlArt);
		if (relayState != NULL) {
			profile->msg_relayState = g_strdup(relayState);
		}
	}
	xmlFree(url);
	xmlFree(b64_samlArt);
	xmlFree(relayState);

	if (strcmp(LASSO_SAMLP_RESPONSE(profile->response)->Status->StatusCode->Value,
				"samlp:Success") != 0) {
		if (profile->session == NULL)
			profile->session = lasso_session_new();

		lasso_session_add_status(profile->session, profile->remote_providerID,
				g_object_ref(LASSO_SAMLP_RESPONSE(profile->response)->Status));
	}

	return ret;
}

/**
 * lasso_login_build_authn_request_msg:
 * @login: a #LassoLogin
 * 
 * Converts profile authentication request (@request member) into a Liberty
 * message, either an URL in HTTP-Redirect profile or an URL and a field value
 * in Browser-POST (form) profile.
 *
 * The URL is set into the @msg_url member and the eventual field value (LAREQ)
 * is set into the @msg_body member.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_build_authn_request_msg(LassoLogin *login)
{
	LassoProvider *provider, *remote_provider;
	LassoProfile *profile;
	char *md_authnRequestsSigned, *url, *query, *lareq, *protocolProfile;
	LassoProviderRole role;
	gboolean must_sign;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	profile = LASSO_PROFILE(login);

	provider = LASSO_PROVIDER(profile->server);
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	protocolProfile = LASSO_LIB_AUTHN_REQUEST(profile->request)->ProtocolProfile;
	if (protocolProfile == NULL)
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;

	role = provider->role;
	provider->role = LASSO_PROVIDER_ROLE_SP; /* we act as an SP for sure here */

	if (lasso_provider_has_protocol_profile(remote_provider,
				LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON, protocolProfile) == FALSE) {
		provider->role = role;
		return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
	}

	/* check if authnRequest must be signed */
	md_authnRequestsSigned = lasso_provider_get_metadata_one(provider, "AuthnRequestsSigned");
	must_sign = (md_authnRequestsSigned && strcmp(md_authnRequestsSigned, "true") == 0);
	g_free(md_authnRequestsSigned);
	provider->role = role;

	if (login->http_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* REDIRECT -> query */
		if (must_sign) {
			query = lasso_node_export_to_query(LASSO_NODE(profile->request),
					profile->server->signature_method,
					profile->server->private_key);
		} else {
			query = lasso_node_export_to_query(
					LASSO_NODE(profile->request), 0, NULL);
		}
		if (query == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}

		/* get SingleSignOnServiceURL metadata */
		url = lasso_provider_get_metadata_one(remote_provider, "SingleSignOnServiceURL");
		if (url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}

		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		profile->msg_body = NULL;
		g_free(query);
		g_free(url);
	}
	if (login->http_method == LASSO_HTTP_METHOD_POST) {
		if (must_sign) {
			profile->request->private_key_file = profile->server->private_key;
			profile->request->certificate_file = profile->server->certificate;
		}
		lareq = lasso_node_export_to_base64(LASSO_NODE(profile->request));

		if (lareq == NULL) {
			message(G_LOG_LEVEL_CRITICAL,
					"Failed to export AuthnRequest (Base64 encoded).");
			return -5;
		}

		profile->msg_url = lasso_provider_get_metadata_one(
				remote_provider, "SingleSignOnServiceURL");
		profile->msg_body = lareq;
	}

	return ret;
}

/**
 * lasso_login_build_authn_response_msg:
 * @login: a #LassoLogin
 * 
 * Converts profile authentication response (@response member) into a Liberty
 * message.
 *
 * The URL is set into the @msg_url member and the field value (LARES) is set
 * into the @msg_body member.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_build_authn_response_msg(LassoLogin *login)
{
	LassoProvider *remote_provider;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	/* ProtocolProfile must be BrwsPost */
	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	if (login->assertion) {
		LassoSamlAssertion *assertion = login->assertion;
		LassoSamlSubjectStatementAbstract *ss;
		ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement);
		ss->Subject->SubjectConfirmation->ConfirmationMethod = g_list_append(NULL,
				g_strdup(LASSO_SAML_CONFIRMATION_METHOD_BEARER));
	}

	/* Countermeasure: The issuer should sign <lib:AuthnResponse> messages.
	 * (binding and profiles (1.2errata2, page 65) */
	if (profile->server->certificate)
		profile->response->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	else
		profile->response->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	profile->response->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	profile->response->private_key_file = profile->server->private_key;
	profile->response->certificate_file = profile->server->certificate;

	/* build an lib:AuthnResponse base64 encoded */
	profile->msg_body = lasso_node_export_to_base64(LASSO_NODE(profile->response));

	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	profile->msg_url = lasso_provider_get_assertion_consumer_service_url(remote_provider,
			LASSO_LIB_AUTHN_REQUEST(profile->request)->AssertionConsumerServiceID);

	return 0;
}

/**
 * lasso_login_build_request_msg:
 * @login: a #LassoLogin
 * 
 * Converts profile artifact request into a Liberty SOAP message.
 *
 * The URL is set into the @msg_url member and the SOAP message is set into the
 * @msg_body member.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_build_request_msg(LassoLogin *login)
{
	LassoProvider *remote_provider;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	profile->request->private_key_file = profile->server->private_key;
	profile->request->certificate_file = profile->server->certificate;
	LASSO_PROFILE(login)->msg_body = lasso_node_export_to_soap(LASSO_NODE(profile->request));

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}
	profile->msg_url = lasso_provider_get_metadata_one(remote_provider, "SoapEndpoint");
	return 0;
}

/**
 * lasso_login_build_response_msg:
 * @login: a #LassoLogin
 * @remote_providerID: service provider ID
 * 
 * Converts profile assertion response (@response member) into a Liberty SOAP
 * messageresponse message.
 *
 * The URL is set into the @msg_url member and the SOAP message is set into the
 * @msg_body member.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_build_response_msg(LassoLogin *login, gchar *remote_providerID)
{
	LassoProvider *remote_provider;
	LassoProfile *profile;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), -1);
	profile = LASSO_PROFILE(login);

	profile->response = lasso_samlp_response_new();
	profile->response->InResponseTo = g_strdup(profile->request->RequestID);
	if (profile->request->MajorVersion == 1 && profile->request->MinorVersion == 0) {
		/* this is a SAML 1.0 request, must create SAML 1.0 response */
		profile->response->MinorVersion = 0;
	}

	if (profile->server->certificate) {
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->sign_type = 
			LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->sign_type = 
			LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->sign_method = 
		LASSO_SIGNATURE_METHOD_RSA_SHA1;

	if (remote_providerID != NULL) {
		profile->remote_providerID = g_strdup(remote_providerID);
		remote_provider = g_hash_table_lookup(profile->server->providers,
				profile->remote_providerID);
		ret = lasso_provider_verify_signature(remote_provider,
				login->private_data->soap_request_msg,
				"RequestID", LASSO_MESSAGE_FORMAT_SOAP);
		g_free(login->private_data->soap_request_msg);
		login->private_data->soap_request_msg = NULL;

		/* change status code into RequestDenied if signature is
		 * invalid or not found or if an error occurs during
		 * verification */
		if (ret != 0) {
			lasso_profile_set_response_status(profile,
					LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		}

		if (profile->session && ret == 0) {
			/* get assertion in session and add it in response */
			LassoSamlAssertion *assertion;
			LassoSamlpStatus *status;

			status = lasso_session_get_status(profile->session, remote_providerID);
			assertion = lasso_session_get_assertion(profile->session,
					profile->remote_providerID);
			if (status) {
				lasso_node_destroy(LASSO_NODE(LASSO_SAMLP_RESPONSE(
								profile->response)->Status));
				LASSO_SAMLP_RESPONSE(profile->response)->Status =
					g_object_ref(status);
				lasso_session_remove_status(profile->session,
						remote_providerID);
			} else if (assertion) {
				LASSO_SAMLP_RESPONSE(profile->response)->Assertion =
					g_list_append(NULL, g_object_ref(assertion));
				lasso_profile_set_response_status(profile,
						LASSO_SAML_STATUS_CODE_SUCCESS);
				lasso_session_remove_status(profile->session, remote_providerID);
			}
		}
	} else {
		lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
	}

	profile->response->private_key_file = profile->server->private_key;
	profile->response->certificate_file = profile->server->certificate;
	profile->msg_body = lasso_node_export_to_soap(LASSO_NODE(profile->response));

	return ret;
}

/**
 * lasso_login_destroy:
 * @login: a #LassoLogin
 * 
 * Destroys a #LassoLogin object.
 **/
void
lasso_login_destroy(LassoLogin *login)
{
	lasso_node_destroy(LASSO_NODE(login));
}

/**
 * lasso_login_init_authn_request:
 * @login: a #LassoLogin
 * @remote_providerID: the providerID of the identity provider (may be NULL)
 * @http_method: HTTP method to use for request transmission
 *
 * Initializes a new lib:AuthnRequest from current service provider to remote
 * identity provider specified in @remote_providerID (if NULL the first known
 * identity provider is used).
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_init_authn_request(LassoLogin *login, const gchar *remote_providerID,
		LassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (http_method != LASSO_HTTP_METHOD_REDIRECT && http_method != LASSO_HTTP_METHOD_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	profile = LASSO_PROFILE(login);

	/* clean state */
	if (profile->remote_providerID)
		g_free(profile->remote_providerID);
	if (profile->request)
		lasso_node_destroy(LASSO_NODE(profile->request));

	if (remote_providerID != NULL) {
		profile->remote_providerID = g_strdup(remote_providerID);
	} else {
		profile->remote_providerID = lasso_server_get_first_providerID(profile->server);
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	login->http_method = http_method;

	profile->request = LASSO_SAMLP_REQUEST_ABSTRACT(lasso_lib_authn_request_new());
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	profile->request->RequestID = lasso_build_unique_id(32);
	profile->request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	profile->request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	if (lasso_provider_compatibility_level(remote_provider) < LIBERTY_1_2) {
		profile->request->MajorVersion = 1;
		profile->request->MinorVersion = 0;
	}
	profile->request->IssueInstant = lasso_get_current_time();
	LASSO_LIB_AUTHN_REQUEST(profile->request)->ProviderID = g_strdup(
			LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_LIB_AUTHN_REQUEST(profile->request)->RelayState = g_strdup(profile->msg_relayState);

	if (http_method == LASSO_HTTP_METHOD_POST) {
		profile->request->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
		if (profile->server->certificate) {
			profile->request->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
		} else {
			profile->request->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
		}
	}

	return 0;
}


/**
 * lasso_login_init_request:
 * @login: a #LassoLogin
 * @response_msg: the authentication response received
 * @response_http_method: the method used to receive the authentication
 *      response
 *
 * Initializes an artifact request.  @response_msg is either the query string
 * (in redirect mode) or the form LAREQ field (in browser-post mode).
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/ 
gint
lasso_login_init_request(LassoLogin *login, gchar *response_msg,
		LassoHttpMethod response_http_method)
{
	char **query_fields;
	gint ret = 0;
	int i;
	char *artifact_b64 = NULL, *provider_succinct_id_b64;
	char provider_succinct_id[21];
	char artifact[43];
	LassoSamlpRequestAbstract *request;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	if (response_http_method != LASSO_HTTP_METHOD_REDIRECT &&
			response_http_method != LASSO_HTTP_METHOD_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	/* rebuild response (artifact) */
	if (response_http_method == LASSO_HTTP_METHOD_REDIRECT) {
		query_fields = urlencoded_to_strings(response_msg);
		for (i=0; query_fields[i]; i++) {
			if (strncmp(query_fields[i], "SAMLart=", 8) != 0) {
				xmlFree(query_fields[i]);
				continue;
			}
			artifact_b64 = g_strdup(query_fields[i]+8);
			xmlFree(query_fields[i]);
		}
		g_free(query_fields);
	}
	if (response_http_method == LASSO_HTTP_METHOD_POST) {
		artifact_b64 = g_strdup(response_msg);
	}

	i = xmlSecBase64Decode(artifact_b64, artifact, 43);
	if (i < 0 || i > 42) {
		g_free(artifact_b64);
		return LASSO_ERROR_UNDEFINED;
	}

	if (artifact[0] != 0 || artifact[1] != 3) { /* wrong type code */
		g_free(artifact_b64);
		return LASSO_ERROR_UNDEFINED;
	}

	memcpy(provider_succinct_id, artifact+2, 20);
	provider_succinct_id[20] = 0;

	provider_succinct_id_b64 = xmlSecBase64Encode(provider_succinct_id, 20, 0);

	LASSO_PROFILE(login)->remote_providerID = lasso_server_get_providerID_from_hash(
			LASSO_PROFILE(login)->server, provider_succinct_id_b64);
	xmlFree(provider_succinct_id_b64);
	if (LASSO_PROFILE(login)->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	request = LASSO_SAMLP_REQUEST_ABSTRACT(lasso_samlp_request_new());
	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_SAML_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_SAML_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();

	LASSO_SAMLP_REQUEST(request)->AssertionArtifact = artifact_b64;
	if (LASSO_PROFILE(login)->server->certificate) {
		request->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		request->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	request->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;

	LASSO_PROFILE(login)->request = LASSO_SAMLP_REQUEST_ABSTRACT(request);
	
	return ret;
}

/**
 * lasso_login_init_idp_initiated_authn_request:
 * @login: a #LassoLogin.
 * @remote_providerID: the providerID of the remote service provider (may be
 *      NULL)
 * 
 * Generates an authentication response without matching authentication
 * request.
 *
 * If @remote_providerID is NULL, the first known provider is used.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_init_idp_initiated_authn_request(LassoLogin *login,
		const gchar *remote_providerID)
{
	int rc;
	LassoProfile *profile;

	rc = lasso_login_init_authn_request(login, remote_providerID, LASSO_HTTP_METHOD_POST);
	if (rc)
		return rc;
	profile = LASSO_PROFILE(login);

	/* no RequestID attribute or it would be used in response assertion */
	g_free(profile->request->RequestID);
	profile->request->RequestID = NULL;
	LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy = LASSO_LIB_NAMEID_POLICY_TYPE_ANY;

	return 0;
}

/**
 * lasso_login_must_ask_for_consent:
 * @login: a #LassoLogin
 * 
 * Evaluates if consent must be asked to the Principal to federate him.
 * 
 * Return value: %TRUE if consent must be asked
 **/
gboolean
lasso_login_must_ask_for_consent(LassoLogin *login)
{
	if (lasso_login_must_ask_for_consent_private(login)) {
		if (LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->IsPassive)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}


/**
 * lasso_login_must_authenticate:
 * @login: a #LassoLogin
 * 
 * Evaluates if user must be authenticated.
 * 
 * Return value: %TRUE if user must be authenticated
 **/
gboolean
lasso_login_must_authenticate(LassoLogin *login)
{
	LassoLibAuthnRequest *request;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
	if (request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
	}

	/* get IsPassive and ForceAuthn in AuthnRequest if exists */
	if ((request->ForceAuthn || LASSO_PROFILE(login)->session == NULL) &&
			request->IsPassive == FALSE)
		return TRUE;
	
	if (LASSO_PROFILE(login)->identity == NULL && request->IsPassive &&
			login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_LIB_STATUS_CODE_NO_PASSIVE);
		return FALSE;
	}

	return FALSE;
}

/**
 * lasso_login_process_authn_request_msg:
 * @login: a #LassoLogin
 * @authn_request_msg: the authentication request received
 *
 * Processes received authentication request, checks it is signed correctly,
 * checks if requested protocol profile is supported, etc.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_process_authn_request_msg(LassoLogin *login, const char *authn_request_msg)
{
	LassoProvider *remote_provider;
	gchar *protocolProfile;
	gchar *authnRequestSigned;
	gboolean must_verify_signature = FALSE;
	gint ret = 0;
	LassoLibAuthnRequest *request;
	LassoMessageFormat format;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	if (authn_request_msg == NULL) {
		format = 0;
		if (profile->request == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
		}

		/* LibAuthnRequest already set by lasso_login_init_idp_initiated_authn_request() */
		request = LASSO_LIB_AUTHN_REQUEST(profile->request);
		
		/* verify that NameIDPolicy is 'any' */
		if (request->NameIDPolicy == NULL)
			return LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
			
		if (strcmp(request->NameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0)
			return LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
	} else {
		request = lasso_lib_authn_request_new();
		format = lasso_node_init_from_message(LASSO_NODE(request), authn_request_msg);
		if (format == LASSO_MESSAGE_FORMAT_UNKNOWN ||
				format == LASSO_MESSAGE_FORMAT_ERROR) {
			return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
		}
		
		profile->request = LASSO_SAMLP_REQUEST_ABSTRACT(request);

		/* get remote ProviderID */
		profile->remote_providerID = g_strdup(
				LASSO_LIB_AUTHN_REQUEST(profile->request)->ProviderID);

	}


	/* get ProtocolProfile in lib:AuthnRequest */
	protocolProfile = LASSO_LIB_AUTHN_REQUEST(profile->request)->ProtocolProfile;
	if (protocolProfile == NULL ||
			strcmp(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART) == 0) {
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
	} else if (strcmp(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST) == 0) {
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST;
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
	} else {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	/* check if requested single sign on protocol profile is supported */
	LASSO_PROVIDER(profile->server)->role = LASSO_PROVIDER_ROLE_IDP;
	if (lasso_provider_has_protocol_profile(
				LASSO_PROVIDER(profile->server),
				LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON,
				protocolProfile) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
	}

	/* Check authnRequest signature. */
	if (authn_request_msg != NULL) {
		remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
		if (remote_provider != NULL) {
			/* Is authnRequest signed ? */
			authnRequestSigned = lasso_provider_get_metadata_one(
					remote_provider, "AuthnRequestsSigned");
			if (authnRequestSigned != NULL) {
				must_verify_signature = strcmp(authnRequestSigned, "true") == 0;
				g_free(authnRequestSigned);
			} else {
				/* missing element in metadata; shouldn't
				 * happen, assume true */
				must_verify_signature = TRUE;
			}
		} else {
			return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
		}

		/* verify request signature */
		if (must_verify_signature) {
			ret = lasso_provider_verify_signature(remote_provider,
					authn_request_msg, "RequestID", format);
			profile->signature_status = ret;
		}
	}

	/* create LibAuthnResponse */
	profile->response = lasso_lib_authn_response_new(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_LIB_AUTHN_REQUEST(profile->request));
	if (profile->request->MajorVersion == 1 && profile->request->MinorVersion < 2) {
		/* pre-id-ff 1.2, move accordingly */
		profile->response->MajorVersion = 1;
		profile->response->MinorVersion = 0;
	}


	return ret;
}

/**
 * lasso_login_process_authn_response_msg:
 * @login: a #LassoLogin
 * @authn_response_msg: the authentication response received
 *
 * Processes received authentication response.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg)
{
	gint ret1 = 0, ret2 = 0;
	LassoMessageFormat format;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(authn_response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	
	/* clean state */
	if (LASSO_PROFILE(login)->remote_providerID)
		g_free(LASSO_PROFILE(login)->remote_providerID);
	if (LASSO_PROFILE(login)->response)
		lasso_node_destroy(LASSO_NODE(LASSO_PROFILE(login)->response));

	LASSO_PROFILE(login)->response = lasso_lib_authn_response_new(NULL, NULL);
	format = lasso_node_init_from_message(
			LASSO_NODE(LASSO_PROFILE(login)->response), authn_response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	LASSO_PROFILE(login)->remote_providerID = g_strdup(
			LASSO_LIB_AUTHN_RESPONSE(LASSO_PROFILE(login)->response)->ProviderID);

	if (LASSO_PROFILE(login)->remote_providerID == NULL) {
		ret1 = critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	LASSO_PROFILE(login)->msg_relayState = g_strdup(LASSO_LIB_AUTHN_RESPONSE(
			LASSO_PROFILE(login)->response)->RelayState);

	LASSO_PROFILE(login)->signature_status = lasso_provider_verify_signature(
			remote_provider, authn_response_msg, "ResponseID", format);
	ret2 = lasso_login_process_response_status_and_assertion(login);

	/* XXX: and what about signature_status ?  Shouldn't it return error on
	 * failure ? */
	return ret2 == 0 ? ret1 : ret2;
}


/**
 * lasso_login_process_request_msg:
 * @login: a #LassoLogin
 * @request_msg: the artifact request received
 *
 * Processes received artifact request.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_process_request_msg(LassoLogin *login, gchar *request_msg)
{
	gint ret = 0;
	LassoProfile *profile = LASSO_PROFILE(login);

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* rebuild samlp:Request with request_msg */
	profile->request = LASSO_SAMLP_REQUEST_ABSTRACT(lasso_node_new_from_soap(request_msg));
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	/* get AssertionArtifact */
	login->assertionArtifact = g_strdup(
			LASSO_SAMLP_REQUEST(profile->request)->AssertionArtifact);

	/* Keep a copy of request msg so signature can be verified when we get
	 * the providerId in lasso_login_build_response_msg()
	 */
	login->private_data->soap_request_msg = g_strdup(request_msg);

	return ret;
}


/**
 * lasso_login_process_response_msg:
 * @login: a #LassoLogin
 * @response_msg: the assertion response received
 *
 * Processes received assertion response.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_process_response_msg(LassoLogin *login, gchar *response_msg)
{
	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* rebuild samlp:Response with response_msg */
	LASSO_PROFILE(login)->response = LASSO_SAMLP_RESPONSE_ABSTRACT(
			lasso_node_new_from_soap(response_msg));
	if (! LASSO_IS_SAMLP_RESPONSE(LASSO_PROFILE(login)->response) ) {
		lasso_node_destroy(LASSO_NODE(LASSO_PROFILE(login)->response));
		LASSO_PROFILE(login)->response = NULL;
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	return lasso_login_process_response_status_and_assertion(login);
}


/**
 * lasso_login_set_encryptedResourceId:
 * @login: a #LassoLogin
 * @encryptedResourceId:
 *
 * ...
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_login_set_encryptedResourceId(LassoLogin *login,
				    LassoDiscoEncryptedResourceID *encryptedResourceId)
{
#ifdef LASSO_WSF_ENABLED
	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_ENCRYPTED_RESOURCE_ID(encryptedResourceId),
			     LASSO_PARAM_ERROR_INVALID_VALUE);

	login->private_data->encryptedResourceId = g_object_ref(encryptedResourceId);
#endif

	return 0;
}


/**
 * lasso_login_set_resourceId:
 * @login: a #LassoLogin
 * @content:
 *
 * ...
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_login_set_resourceId(LassoLogin *login, const char *content)
{
#ifdef LASSO_WSF_ENABLED
	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(content != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	login->private_data->resourceId = lasso_disco_resource_id_new(content);
#endif
	return 0;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AssertionArtifact", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLogin, assertionArtifact) },
	{ "NameIDPolicy", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLogin, nameIDPolicy) },
	{ "Assertion", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoLogin, assertion) },
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoLogin *login = LASSO_LOGIN(node);

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlSetProp(xmlnode, "LoginDumpVersion", "2");

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART)
		xmlNewTextChild(xmlnode, NULL, "ProtocolProfile", "Artifact");
	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST)
		xmlNewTextChild(xmlnode, NULL, "ProtocolProfile", "POST");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLogin *login = LASSO_LOGIN(node);
	xmlNode *t;
	int rc;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "ProtocolProfile") == 0) {
			char *s;
			s = xmlNodeGetContent(t);
			if (strcmp(s, "Artifact") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
			if (strcmp(s, "POST") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
			xmlFree(s);
		}
		t = t->next;
	}
	return 0;
}


/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoLogin *login = LASSO_LOGIN(object);
	g_free(login->private_data->soap_request_msg);
	login->private_data->soap_request_msg = NULL;
	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{  
	LassoLogin *login = LASSO_LOGIN(object);
	g_free(login->private_data);
	login->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoLogin *login)
{
	login->private_data = g_new(LassoLoginPrivate, 1);
	login->private_data->soap_request_msg = NULL;

	login->protocolProfile = 0;
	login->assertionArtifact = NULL;
	login->nameIDPolicy = NULL;
	login->http_method = 0;
}

static void
class_init(LassoLoginClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Login");
	lasso_node_class_add_snippets(nclass, schema_snippets);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_login_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoLoginClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLogin),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoLogin", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_login_new
 * @server: the #LassoServer
 *
 * Creates a new #LassoLogin.
 *
 * Return value: a newly created #LassoLogin object; or NULL if an error
 *     occured
 **/
LassoLogin*
lasso_login_new(LassoServer *server)
{
	LassoLogin *login = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	login = g_object_new(LASSO_TYPE_LOGIN, NULL);
	LASSO_PROFILE(login)->server = g_object_ref(server);

	return login;
}

/**
 * lasso_login_new_from_dump:
 * @server: the #LassoServer
 * @dump: XML login dump
 *
 * Restores the @dump to a new #LassoLogin.
 *
 * Return value: a newly created #LassoLogin; or NULL if an error occured.
 **/
LassoLogin*
lasso_login_new_from_dump(LassoServer *server, const gchar *dump)
{
	LassoLogin *login;
	xmlDoc *doc;

	login = g_object_new(LASSO_TYPE_LOGIN, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(login), xmlDocGetRootElement(doc)); 
	LASSO_PROFILE(login)->server = g_object_ref(server);

	return login;
}

/**
 * lasso_login_dump:
 * @login: a #LassoLogin
 *
 * Dumps @login content to an XML string.
 *
 * Return value: the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_login_dump(LassoLogin *login)
{
	return lasso_node_dump(LASSO_NODE(login));
}


/**
 * lasso_login_validate_request_msg:
 * @login: a #LassoLogin
 * @authentication_result: whether user has authenticated succesfully
 * @is_consent_obtained: whether user consent has been obtained
 *
 * Initializes a response to the authentication request received.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_login_validate_request_msg(LassoLogin *login, gboolean authentication_result,
		gboolean is_consent_obtained)
{
	LassoProfile *profile;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	/* modify AuthnResponse StatusCode if user authentication is not OK */
	if (authentication_result == FALSE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
		return LASSO_LOGIN_ERROR_REQUEST_DENIED;
	}

	/* if signature is not OK => modify AuthnResponse StatusCode */
	if (profile->signature_status == LASSO_DS_ERROR_INVALID_SIGNATURE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
		return LASSO_LOGIN_ERROR_INVALID_SIGNATURE;
	}

	if (profile->signature_status == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		/* Unsigned AuthnRequest */
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST);
		return LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST;
	}

	if (profile->signature_status == 0 && authentication_result == TRUE) {
		/* process federation */
		ret = lasso_login_process_federation(login, is_consent_obtained);
		if (ret != 0)
			return ret;
	}

	lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_SUCCESS);

	return ret;
}
