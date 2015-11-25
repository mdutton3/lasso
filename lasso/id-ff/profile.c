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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * SECTION:profile
 * @short_description: Base class for all identity profiles
 *
 **/

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "../xml/samlp_response.h"
#include "../xml/samlp_request.h"
#include "../xml/lib_authn_response.h"
#include "../xml/lib_status_response.h"

#include "profile.h"
#include "profileprivate.h"
#include "providerprivate.h"
#include "sessionprivate.h"

#include "../saml-2.0/profileprivate.h"
#include "../xml/saml-2.0/saml2_name_id.h"
#include "../xml/saml_name_identifier.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../utils.h"
#include "../debug.h"
#ifdef LASSO_WSF_ENABLED
#include "../xml/idwsf_strings.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#endif
#include "../lasso_config.h"

#include <stdio.h>

/*****************************************************************************/
/* public functions                                                          */
/*****************************************************************************/

static LassoNode*
_lasso_saml_assertion_get_name_id(LassoSamlAssertion *assertion) 
{
	LassoSamlAuthenticationStatement *authn_statement;
	LassoSamlSubject *subject;

	goto_cleanup_if_fail(LASSO_IS_SAML_ASSERTION(assertion));
	authn_statement = assertion->AuthenticationStatement;
	goto_cleanup_if_fail(LASSO_IS_SAML_AUTHENTICATION_STATEMENT(authn_statement));
	subject = authn_statement->parent.Subject;
	goto_cleanup_if_fail(LASSO_IS_SAML_SUBJECT(subject));
	if (LASSO_IS_SAML_NAME_IDENTIFIER(subject->NameIdentifier))
		return (LassoNode*)subject->NameIdentifier;
cleanup:
	return NULL;
}

static LassoNode*
_lasso_saml2_assertion_get_name_id(LassoSaml2Assertion *assertion)
{
	LassoSaml2Subject *subject;

	goto_cleanup_if_fail(LASSO_SAML2_ASSERTION(assertion));
	subject = assertion->Subject;
	goto_cleanup_if_fail(LASSO_SAML2_SUBJECT(subject));
	if (LASSO_IS_SAML2_NAME_ID(subject->NameID))
		return (LassoNode*)subject->NameID;

cleanup:
	return NULL;
}

/**
 * lasso_profile_get_nameIdentifier:
 * @profile: a #LassoProfile
 *
 * Looks up appropriate federation in object and gets the service provider name
 * identifier (which is actually a #LassoSamlNameIdentifier in ID-FF 1.2 and
 * #LassoSaml2NameID in SAML 2.0).
 *
 * Return value:(transfer none): the name identifier or NULL if none was found.  The #LassoNode
 *     object is internally allocated and must not be freed by the caller.
 **/
LassoNode*
lasso_profile_get_nameIdentifier(LassoProfile *profile)
{
	LassoProvider *remote_provider;
	LassoFederation *federation;
	const char *name_id_sp_name_qualifier;

	if (!LASSO_IS_PROFILE(profile)) {
		return NULL;
	}

	if (profile->remote_providerID == NULL)
		return NULL;

	/* For transient federations, we must look at assertions no federation object exists */
	if (LASSO_IS_SESSION(profile->session)) {
		LassoNode *assertion, *name_id;

		assertion = lasso_session_get_assertion(profile->session,
				profile->remote_providerID);

		name_id = _lasso_saml_assertion_get_name_id((LassoSamlAssertion*)assertion);
		if (name_id)
			return name_id;
		name_id = _lasso_saml2_assertion_get_name_id((LassoSaml2Assertion*)assertion);
		if (name_id)
			return name_id;
	}
	/* beware, it is not a real loop ! */
	if (LASSO_IS_IDENTITY(profile->identity)) do {
		remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (remote_provider == NULL)
			break;

		name_id_sp_name_qualifier = lasso_provider_get_sp_name_qualifier(remote_provider);
		if (name_id_sp_name_qualifier == NULL)
			break;

		federation = g_hash_table_lookup(
				profile->identity->federations,
				name_id_sp_name_qualifier);
		if (federation == NULL)
			break;

		if (federation->remote_nameIdentifier)
			return federation->remote_nameIdentifier;
		return federation->local_nameIdentifier;
	} while (FALSE);

	return NULL;
}

/**
 * lasso_profile_get_request_type_from_soap_msg:
 * @soap: the SOAP message
 *
 * Looks up and return the type of the request in a SOAP message.
 *
 * Return value: the type of request
 **/
LassoRequestType
lasso_profile_get_request_type_from_soap_msg(const gchar *soap)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	LassoRequestType type = LASSO_REQUEST_TYPE_INVALID;
	const char *name = NULL;
	xmlNs *ns = NULL;
	xmlError error;

	memset(&error, 0, sizeof(xmlError));
	if (soap == NULL)
		return LASSO_REQUEST_TYPE_INVALID;

	doc = lasso_xml_parse_memory_with_error(soap, strlen(soap), &error);
	if (! doc) {
		message(G_LOG_LEVEL_WARNING, "Invalid soap message: %s", error.message);
		type = LASSO_REQUEST_TYPE_INVALID;
		goto cleanup;
	}
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body/*", xpathCtx);

	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		name = (char*)xpathObj->nodesetval->nodeTab[0]->name;
		ns = xpathObj->nodesetval->nodeTab[0]->ns;
	}

	if (name == NULL || ns == NULL) {
		message(G_LOG_LEVEL_WARNING, "Invalid SOAP request");
	} else if (strcmp(name, "Request") == 0) {
		type = LASSO_REQUEST_TYPE_LOGIN;
	} else if (strcmp(name, "LogoutRequest") == 0) {
		type = LASSO_REQUEST_TYPE_LOGOUT;
	} else if (strcmp(name, "FederationTerminationNotification") == 0) {
		type = LASSO_REQUEST_TYPE_DEFEDERATION;
	} else if (strcmp(name, "RegisterNameIdentifierRequest") == 0) {
		type = LASSO_REQUEST_TYPE_NAME_REGISTRATION;
	} else if (strcmp(name, "NameIdentifierMappingRequest") == 0) {
		type = LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING;
	} else if (strcmp(name, "AuthnRequest") == 0) {
		type = LASSO_REQUEST_TYPE_LECP;
	} else if (strcmp(name, "ManageNameIDRequest") == 0) {
		type = LASSO_REQUEST_TYPE_NAME_ID_MANAGEMENT;
#ifdef LASSO_WSF_ENABLED
	} else if (strcmp(name, "Query") == 0) {
		if (strcmp((char*)ns->href, LASSO_DISCO_HREF) == 0) {
			type = LASSO_REQUEST_TYPE_DISCO_QUERY;
		} else if (strcmp((char*)ns->href, LASSO_IDWSF2_DISCOVERY_HREF) == 0) {
			type = LASSO_REQUEST_TYPE_IDWSF2_DISCO_QUERY;
		} else {
			type = LASSO_REQUEST_TYPE_DST_QUERY;
		}
	} else if (strcmp(name, "Modify") == 0) {
		if (strcmp((char*)ns->href, LASSO_DISCO_HREF) == 0) {
			type = LASSO_REQUEST_TYPE_DISCO_MODIFY;
		} else {
			type = LASSO_REQUEST_TYPE_DST_MODIFY;
		}
	} else if (strcmp(name, "SASLRequest") == 0) {
		type = LASSO_REQUEST_TYPE_SASL_REQUEST;
	} else if (strcmp(name, "SvcMDRegister") == 0) {
		type = LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_REGISTER;
	} else if (strcmp(name, "SvcMDAssociationAdd") == 0) {
		type = LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_ASSOCIATION_ADD;
#endif
	} else {
		message(G_LOG_LEVEL_WARNING, "Unknown node name : %s", name);
	}

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
cleanup:
	lasso_release_doc(doc);
	xmlResetError(&error);
	return type;
}

/**
 * lasso_profile_is_liberty_query:
 * @query: HTTP query string
 *
 * Tests the query string to know if the URL is called as the result of a
 * Liberty redirect (action initiated elsewhere) or not.
 *
 * Return value: TRUE if Liberty query, FALSE otherwise
 **/
gboolean
lasso_profile_is_liberty_query(const gchar *query)
{
	/* logic is that a lasso query always has some parameters (RequestId,
	 * MajorVersion, MinorVersion, IssueInstant, ProviderID,
	 * NameIdentifier, NameQualifier, Format).  If three of them are there;
	 * it's a lasso query, possibly broken, but a lasso query nevertheless.
	 */
	gchar *parameters[] = {
		"RequestId=", "MajorVersion=", "MinorVersion=", "IssueInstant=",
		"ProviderID=", "NameIdentifier=", "NameQualifier=", "Format=",
		NULL };
	gint i, n = 0;

	for (i=0; parameters[i] && n < 3; i++) {
		if (strstr(query, parameters[i]))
			n++;
	}

	return (n == 3);
}


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/


/**
 * lasso_profile_get_identity:
 * @profile: a #LassoProfile
 *
 * Gets the identity bound to @profile.
 *
 * Return value:(transfer none): the identity or NULL if it none was found.  The #LassoIdentity
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoIdentity*
lasso_profile_get_identity(LassoProfile *profile)
{
	if (profile->identity && g_hash_table_size(profile->identity->federations))
		return profile->identity;
	return NULL;
}


/**
 * lasso_profile_get_session:
 * @profile: a #LassoProfile
 *
 * Gets the session bound to @profile.
 *
 * Return value:(transfer none): the session or NULL if it none was found.  The #LassoSession
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoSession*
lasso_profile_get_session(LassoProfile *profile)
{
	if (profile->session == NULL)
		return NULL;

	if (lasso_session_is_empty(profile->session))
		return NULL;

	return profile->session;
}


/**
 * lasso_profile_is_identity_dirty:
 * @profile: a #LassoProfile
 *
 * Checks whether identity has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if identity has changed
 **/
gboolean
lasso_profile_is_identity_dirty(LassoProfile *profile)
{
	return (profile->identity && profile->identity->is_dirty);
}


/**
 * lasso_profile_is_session_dirty:
 * @profile: a #LassoProfile
 *
 * Checks whether session has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if session has changed
 **/
gboolean
lasso_profile_is_session_dirty(LassoProfile *profile)
{
	return LASSO_IS_SESSION(profile->session) && lasso_session_is_dirty(profile->session);
}


void
lasso_profile_set_response_status(LassoProfile *profile, const char *statusCodeValue)
{
	LassoSamlpStatus *status;

	/* protocols-schema 1.2 (errata 2.0), page 9
	 *
	 * 3.1.9. Response Status Codes
	 *
	 * All Liberty response messages use <samlp: StatusCode> elements to
	 * indicate the status of a corresponding request.  Responders MUST
	 * comply with the rules governing <samlp: StatusCode> elements
	 * specified in [SAMLCore11] regarding the use of nested second-, or
	 * lower-level response codes to provide specific information relating
	 * to particular errors. A number of status codes are defined within
	 * the Liberty namespace for use with this specification.
	 */

	status = lasso_samlp_status_new();
	status->StatusCode = lasso_samlp_status_code_new();

	if (strncmp(statusCodeValue, "samlp:", 6) == 0) {
		status->StatusCode->Value = g_strdup(statusCodeValue);
	} else {
		status->StatusCode->Value = g_strdup(LASSO_SAML_STATUS_CODE_RESPONDER);
		status->StatusCode->StatusCode = lasso_samlp_status_code_new();
		status->StatusCode->StatusCode->Value = g_strdup(statusCodeValue);
	}

	if (LASSO_IS_SAMLP_RESPONSE(profile->response)) {
		LassoSamlpResponse *response = LASSO_SAMLP_RESPONSE(profile->response);
		lasso_assign_new_gobject(response->Status, status);
		return;
	}
	if (LASSO_IS_LIB_STATUS_RESPONSE(profile->response)) {
		LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(profile->response);
		lasso_assign_new_gobject(response->Status, status);
		return;
	}

	message(G_LOG_LEVEL_CRITICAL, "Failed to set status");
	g_assert_not_reached();
}

void
lasso_profile_clean_msg_info(LassoProfile *profile)
{
	lasso_release_string(profile->msg_url);
	lasso_release_string(profile->msg_body);
}

/**
 * lasso_profile_set_identity_from_dump:
 * @profile: a #LassoProfile
 * @dump: XML identity dump
 *
 * Builds a new #LassoIdentity object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_profile_set_identity_from_dump(LassoProfile *profile, const gchar *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	lasso_assign_new_gobject(profile->identity, lasso_identity_new_from_dump(dump));
	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP);
	}

	return 0;
}


/**
 * lasso_profile_set_session_from_dump:
 * @profile: a #LassoProfile
 * @dump: XML session dump
 *
 * Builds a new #LassoSession object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_profile_set_session_from_dump(LassoProfile *profile, const gchar *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	lasso_assign_new_gobject(profile->session, lasso_session_new_from_dump(dump));
	if (profile->session == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_SESSION_DUMP);

	IF_SAML2(profile) {
		lasso_saml20_profile_set_session_from_dump(profile);
	}

	return 0;
}

/**
 * lasso_profile_get_artifact:
 * @profile: a #LassoProfile object
 *
 * Return the artifact token
 *
 * Return value:(transfer full)(allow-none): a newly allocated string or NULL.
 */
char*
lasso_profile_get_artifact(LassoProfile *profile)
{
	return g_strdup(profile->private_data->artifact);
}

/**
 * lasso_profile_get_artifact_message:
 * @profile: a #LassoProfile object
 *
 * Return the artifact message.
 *
 * Return value:(transfer full)(allow-none): a newly allocated string or NULL
 */
char*
lasso_profile_get_artifact_message(LassoProfile *profile)
{
	return g_strdup(profile->private_data->artifact_message);
}

/**
 * lasso_profile_set_artifact_message:
 * @profile: a #LassoProfile object
 * @message: the artifact message content
 *
 * Set @message as the content for the ArtifactResolve response.
 *
 */
void
lasso_profile_set_artifact_message(LassoProfile *profile, const char *message)
{
	if (! LASSO_IS_PROFILE(profile)) {
		message(G_LOG_LEVEL_CRITICAL, "set_artifact_message called on something not a" \
			"LassoProfile object: %p", profile);
		return;
	}
	lasso_assign_string(profile->private_data->artifact_message, message);
}

/**
 * lasso_profile_get_server:
 * @profile: a #LassoProfile object
 *
 * Return the #LassoServer linked to this profile object. A profile object should always contains
 * one. It allows to find metadatas of other providers and to know our own metadatas.
 *
 * Return value: (transfer none): a #LassoServer or NULL if profile is not a #LassoProfile or no
 * #LassoServer object was setup at the creation of this profile.
 */
LassoServer*
lasso_profile_get_server(LassoProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_PROFILE(profile), NULL);

	if (profile->server) {
		if (LASSO_IS_SERVER(profile->server)) {
			return profile->server;
		} else {
			message(G_LOG_LEVEL_WARNING, "profile->server contains a non LassoServer object");
		}
	}

	return NULL;
}


/**
 * lasso_profile_get_message_id:
 * @profile: a #LassoProfile object
 *
 * Return the messge ID.
 *
 * Return value:(transfer full)(allow-none): a newly allocated string or NULL
 */
char*
lasso_profile_get_message_id(LassoProfile *profile)
{
	return g_strdup(profile->private_data->message_id);
}

/**
 * lasso_profile_set_message_id:
 * @profile: a #LassoProfile object
 * @message_id: the message ID
 *
 * Set @message_id for the current conversation
 *
 */
void
lasso_profile_set_message_id(LassoProfile *profile, const char *message_id)
{
	if (! LASSO_IS_PROFILE(profile)) {
		message(G_LOG_LEVEL_CRITICAL, "set_message_id called on something not a" \
			"LassoProfile object: %p", profile);
		return;
	}
	lasso_assign_string(profile->private_data->message_id, message_id);
}

/**
 * lasso_profile_get_idp_list:
 * @profile: a #LassoProfile object
 *
 * Return the messge ID.
 *
 * Return value: a #LassoNode, when using SAML 2.0 a #LassoSamlp2IDPList,
 * when using ID-FF a #LassoLibIDPList.
 */
LassoNode*
lasso_profile_get_idp_list(LassoProfile *profile)
{
	return profile->private_data->idp_list;
}

/**
 * lasso_profile_set_idp_list:
 * @profile: a #LassoProfile object
 * @idp_list: a #LassoNode, when using SAML 2.0 a #LassoSamlp2IDPList,
 * when using ID-FF a #LassoLibIDPList.
 *
 * Set @idp_list for the current conversation
 *
 */
void
lasso_profile_set_idp_list(LassoProfile *profile, const LassoNode *idp_list)
{
	if (! LASSO_IS_PROFILE(profile)) {
		message(G_LOG_LEVEL_CRITICAL, "set_idp_list called on something not a" \
			"LassoProfile object: %p", profile);
		return;
	}
	lasso_assign_gobject(profile->private_data->idp_list, idp_list);
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, request), NULL, NULL, NULL},
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, response), NULL, NULL, NULL},
	{ "NameIdentifier", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoProfile, nameIdentifier), NULL, NULL, NULL},
	{ "RemoteProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, remote_providerID),
		NULL, NULL, NULL},
	{ "MsgUrl", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_url), NULL, NULL, NULL},
	{ "MsgBody", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_body), NULL, NULL, NULL},
	{ "MsgRelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_relayState), NULL,
		NULL, NULL},
	{ "HttpRequestMethod", SNIPPET_CONTENT | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoProfile, http_request_method), NULL, NULL, NULL},
	{ "Artifact", SNIPPET_CONTENT | SNIPPET_PRIVATE, G_STRUCT_OFFSET(LassoProfilePrivate,
			artifact), NULL, NULL, NULL },
	{ "ArtifactMessage", SNIPPET_CONTENT | SNIPPET_PRIVATE, G_STRUCT_OFFSET(LassoProfilePrivate,
			artifact_message), NULL, NULL, NULL },
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

/**
 * lasso_profile_set_signature_hint:
 * @profile: a #LassoProfile object
 * @signature_hint: wheter next produced messages should be signed or not (or let Lasso choose from
 * implicit information).
 *
 * By default each profile will choose to sign or not its messages, this method allow to force or
 * forbid the signature of messages, on a per transaction basis.
 */
void
lasso_profile_set_signature_hint(LassoProfile *profile, LassoProfileSignatureHint signature_hint)
{
	if (! LASSO_IS_PROFILE(profile) || ! profile->private_data)
		return;
	profile->private_data->signature_hint = signature_hint;
}

/**
 * lasso_profile_get_signature_hint:
 * @profile: a #LassoProfile object
 *
 * Return the value of the signature hint attribute (see lasso_profile_set_signature_hint()).
 *
 * Return value: a value in the enum type #LassoProfileSignatureHint.
 */
LassoProfileSignatureHint
lasso_profile_get_signature_hint(LassoProfile *profile)
{
	LassoProfileSignatureVerifyHint signature_verify_hint;
	if (! LASSO_IS_PROFILE(profile) || ! profile->private_data)
		return LASSO_PROFILE_SIGNATURE_HINT_MAYBE;
	signature_verify_hint = profile->private_data->signature_verify_hint;
	if (signature_verify_hint >= LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST) {
		message(G_LOG_LEVEL_WARNING, "%u is an invalid signature verify hint",
				signature_verify_hint);
		return LASSO_PROFILE_SIGNATURE_HINT_MAYBE;
	}
	return profile->private_data->signature_hint;
}

/**
 * lasso_profile_set_signature_verify_hint:
 * @profile: a #LassoProfile object
 * @signature_verify_hint: whether next received message signatures should be checked or not (or let
 * Lasso choose from implicit information).
 *
 * By default each profile will choose to verify or not its messages, this method allow to force or
 * forbid the signature of messages, on a per transaction basis.
 */
void
lasso_profile_set_signature_verify_hint(LassoProfile *profile,
		LassoProfileSignatureVerifyHint signature_verify_hint)
{
	if (! LASSO_IS_PROFILE(profile) || ! profile->private_data)
		return;
	if (signature_verify_hint >= LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST) {
		message(G_LOG_LEVEL_WARNING, "%i is an invalid argument for " __FUNCTION__,
				signature_verify_hint);
		return;
	}
	profile->private_data->signature_verify_hint = signature_verify_hint;
}

/**
 * lasso_profile_get_signature_verify_hint:
 * @profile: a #LassoProfile object
 *
 * Return the value of the signature verify hint attribute (see
 * lasso_profile_set_signature_verify_hint()).
 *
 * Return value: a value in the enum type #LassoProfileSignatureVerifyHint.
 */
LassoProfileSignatureVerifyHint
lasso_profile_get_signature_verify_hint(LassoProfile *profile)
{
	if (! LASSO_IS_PROFILE(profile) || ! profile->private_data)
		return LASSO_PROFILE_SIGNATURE_HINT_MAYBE;
	return profile->private_data->signature_verify_hint;
}


/**
 * lasso_profile_set_soap_fault_response:
 * @profile: a #LassoProfile object
 * @faultcode: the code for the SOAP fault
 * @faultstring:(allow-none): the description for the SOAP fault
 * @details:(element-type LassoNode)(allow-none): a list of nodes to add as details
 *
 * Set the response to a SOAP fault, using @faultcode, @faultstring, and @details to initialize it.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_profile_set_soap_fault_response(LassoProfile *profile, const char *faultcode,
		const char *faultstring, GList *details)
{
	LassoSoapFault *fault;

	if (! LASSO_IS_SOAP_FAULT(profile->response)) {
		lasso_release_gobject(profile->response);
		profile->response = (LassoNode*)lasso_soap_fault_new();
	}
	fault = (LassoSoapFault*)profile->response;
	lasso_assign_string(fault->faultcode, faultcode);
	lasso_assign_string(fault->faultstring, faultstring);
	if (details) {
		if (! fault->Detail) {
			fault->Detail = lasso_soap_detail_new();
		}
		lasso_assign_list_of_gobjects(fault->Detail->any, details);
	} else {
		lasso_release_gobject(fault->Detail);
	}
	return 0;
}

/**
 * lasso_profile_sso_role_with:
 * @profile: a #LassoProfile object
 * @remote_provider_id: the identifier of a provider
 *
 * Returns whether the current provider is a service provider relatively to another provider. It
 * uses the #LassoProfile.identity to find if a federation qualifier by the given provider exists or
 * the reverse.
 *
 * Return value: #LASSO_PROVIDER_ROLE_NONE if nothing can be said, #LASSO_PROVIDER_ROLE_SP if a
 * federation qualifier by @remote_provider_id exists or #LASSO_PROVIDER_ROLE_IDP if a federation
 * qualifier by our own #LassoProvider.ProviderID exists.
 */
LassoProviderRole lasso_profile_sso_role_with(LassoProfile *profile, const char *remote_provider_id)
{
	LassoFederation *federation = NULL;
	const char *name_qualifier = NULL;
	const char *provider_id = NULL;


	g_return_val_if_fail(LASSO_IS_PROFILE(profile) && remote_provider_id,
			LASSO_PROVIDER_ROLE_NONE);

	if (profile->server) {
		provider_id = profile->server->parent.ProviderID;
	}

	federation = lasso_identity_get_federation(profile->identity, remote_provider_id);
	if (! federation)
		return LASSO_PROVIDER_ROLE_NONE;

	/* coherency check */
	g_return_val_if_fail(lasso_strisequal(federation->remote_providerID,remote_provider_id),
			LASSO_PROVIDER_ROLE_NONE);

	if (LASSO_IS_SAML2_NAME_ID(federation->local_nameIdentifier)) {
		LassoSaml2NameID *name_id = (LassoSaml2NameID*)federation->local_nameIdentifier;
		name_qualifier = name_id->NameQualifier;
	} else if (LASSO_IS_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier)) {
		LassoSamlNameIdentifier *name_id;

		name_id = (LassoSamlNameIdentifier*)federation->local_nameIdentifier;
		name_qualifier = name_id->NameQualifier;
	} else {
		message(G_LOG_LEVEL_WARNING, "a federation without a NameID was found");
		return LASSO_PROVIDER_ROLE_NONE;
	}
	if (lasso_strisequal(remote_provider_id,name_qualifier)) {
		return LASSO_PROVIDER_ROLE_SP;
	} else if (lasso_strisequal(provider_id,name_qualifier)) {
		return LASSO_PROVIDER_ROLE_IDP;
	}
	return LASSO_PROVIDER_ROLE_NONE;
}

/**
 * lasso_profile_get_signature_status:
 * @profile: a #LassoProfile object
 *
 * Returns the signature status from the last parsed message.
 *
 * Return value: 0 if no error from signature checking occurred, an error code otherwise.
 */
gint
lasso_profile_get_signature_status(LassoProfile *profile)
{
	lasso_bad_param(PROFILE, profile);

	return profile->signature_status;
}

static xmlChar *
extract_issuer(xmlTextReader *reader)
{
	const xmlChar *name;
	const xmlChar *ns_uri;
	xmlNode *node;

	name = xmlTextReaderConstLocalName(reader);
	ns_uri = xmlTextReaderConstNamespaceUri(reader);

	if (strcmp((const char*)name, "Issuer"))
		return NULL;
	if (strcmp((const char*)ns_uri, LASSO_SAML2_ASSERTION_HREF))
		return NULL;
	node = xmlTextReaderExpand(reader);
	return xmlNodeGetContent(node);
}


/**
 * lasso_profile_get_issuer:
 * @message: the HTTP query, POST content or SOAP message
 *
 * Extract the issuer of a message.
 *
 * Return value:(transfer full): Returns the issuer of the given message.
 */
char*
lasso_profile_get_issuer(const char *message)
{
	xmlTextReader *reader;
	char *result = NULL;
	int count = 0, ret;
	xmlChar *xml_result = NULL;
	xmlChar *to_free = NULL;


	reader = lasso_xmltextreader_from_message(message, &to_free);
	if (! reader)
		goto cleanup;
	ret = xmlTextReaderRead(reader);
	while (ret == 1) {
		int node_type = xmlTextReaderNodeType(reader);
		if (node_type == 1) {
			count += 1;
			xml_result = extract_issuer(reader);
			if (xml_result)
				break;
		}
		if (count == 3) {
			break;
		}
		ret = xmlTextReaderRead(reader);
	}
	if (! xml_result)
		goto cleanup;
	result = g_strdup((char *)xml_result);
cleanup:
	if (xml_result)
		lasso_release_xml_string(xml_result);
	if (reader)
		xmlFreeTextReader(reader);
	if (to_free)
		lasso_release_xml_string(to_free);
	return result;
}

/**
 * lasso_profile_get_request_id:
 * @message: the HTTP query, POST content or SOAP message
 *
 * Extract the issuer of a message.
 *
 * Return value:(transfer full): Returns the issuer of the given message.
 */
char*
lasso_profile_get_in_response_to(const char *message)
{
	xmlTextReader *reader;
	char *result = NULL;
	int ret;
	int node_type = 0;
	xmlChar *xml_result = NULL;
	xmlChar *to_free = NULL;


	reader = lasso_xmltextreader_from_message(message, &to_free);
	if (! reader)
		goto cleanup;
	ret = xmlTextReaderRead(reader);
	while (ret == 1) {
		node_type = xmlTextReaderNodeType(reader);
		if (node_type == 1) {
			break;
		}
		ret = xmlTextReaderRead(reader);
	}
	if (node_type != 1)
		goto cleanup;
	xml_result = xmlTextReaderGetAttribute(reader, BAD_CAST "InResponseTo");
	if (! xml_result)
		goto cleanup;
	result = g_strdup((char*)xml_result);
cleanup:
	if (reader)
		xmlFreeTextReader(reader);
	if (xml_result)
		lasso_release_xml_string(xml_result);
	if (to_free)
		lasso_release_xml_string(to_free);
	return result;
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoProfile *profile = LASSO_PROFILE(object);

	if (profile->private_data->dispose_has_run) {
		return;
	}
	profile->private_data->dispose_has_run = TRUE;


	lasso_mem_debug("LassoProfile", "Server", profile->server);
	lasso_release_gobject(profile->server);

	lasso_mem_debug("LassoProfile", "Identity", profile->identity);
	lasso_release_gobject(profile->identity);

	lasso_mem_debug("LassoProfile", "Session", profile->session);
	lasso_release_gobject(profile->session);

	lasso_release_string(profile->private_data->artifact);
	lasso_release_string(profile->private_data->artifact_message);

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(profile));

	lasso_release_gobject(profile->private_data->idp_list);
	lasso_release_string(profile->private_data->message_id);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoProfile *profile)
{
	profile->private_data = LASSO_PROFILE_GET_PRIVATE(profile);
	profile->private_data->dispose_has_run = FALSE;
	profile->private_data->artifact = NULL;
	profile->private_data->artifact_message = NULL;
	profile->private_data->signature_hint = LASSO_PROFILE_SIGNATURE_HINT_MAYBE;
	profile->private_data->message_id = NULL;
	profile->private_data->idp_list = NULL;

	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->nameIdentifier = NULL;
	profile->remote_providerID = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
	profile->msg_relayState = NULL;

	profile->identity = NULL;
	profile->session = NULL;
	profile->signature_status = 0;
}

static void
class_init(LassoProfileClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Profile");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(LassoProfilePrivate));

	G_OBJECT_CLASS(klass)->dispose = dispose;
}

GType
lasso_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoProfile),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoProfile", &this_info, 0);
	}
	return this_type;
}

