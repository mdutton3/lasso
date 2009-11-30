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
#include <xmlsec/base64.h>

#include "../utils.h"
#include "providerprivate.h"
#include "profileprivate.h"
#include "profile.h"

#include "../id-ff/providerprivate.h"
#include "../id-ff/profile.h"
#include "../id-ff/profileprivate.h"
#include "../id-ff/serverprivate.h"
#include <../id-ff/sessionprivate.h>

#include "../xml/private.h"
#include "../xml/saml-2.0/samlp2_request_abstract.h"
#include "../xml/saml-2.0/samlp2_artifact_resolve.h"
#include "../xml/saml-2.0/samlp2_artifact_response.h"
#include "../xml/saml-2.0/samlp2_name_id_mapping_response.h"
#include "../xml/saml-2.0/samlp2_status_response.h"
#include "../xml/saml-2.0/samlp2_response.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../utils.h"
#include "../debug.h"

static char* lasso_saml20_profile_build_artifact(LassoProvider *provider);
G_GNUC_UNUSED static void remove_all_signatures(LassoNode *node);
static int lasso_saml20_profile_export_to_query(LassoProfile *profile, LassoNode *msg, int sign, char **query);

/*
 * Helper functions
 */
static int
get_provider(LassoProfile *profile, LassoProvider **provider_out)
{
	int rc = 0;
	LassoProvider *provider;
	LassoServer *server;

	lasso_bad_param(PROFILE, profile);

	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	provider = lasso_server_get_provider(server, profile->remote_providerID);
	if (! provider) {
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
	}

	*provider_out = provider;
cleanup:
	return 0;

}

static char *
get_url(LassoProvider *provider, char *service, char *binding)
{
	char *meta;
	char *result;

	meta = g_strdup_printf("%s %s", service, binding);
	result = lasso_provider_get_metadata_one(provider, meta);
	lasso_release_string(meta);
	return result;
}

static char *
get_response_url(LassoProvider *provider, char *service, char *binding)
{
	char *meta;
	char *result;

	meta = g_strdup_printf("%s %s ResponseLocation", service, binding);
	result = lasso_provider_get_metadata_one(provider, meta);
	lasso_release_string(meta);
	if (! result) {
		result = get_url(provider, service, binding);
	}
	return result;
}


/**
 * lasso_saml20_profile_generate_artifact
 * @profile: a #LassoProfile
 * @part: 0 for request, 1 for response
 *
 * Generates an artifact for current request or response and sets @profile
 * attributes accordingly.
 *
 * Return value: the generated artifact (internally allocated, don't free)
 **/
char*
lasso_saml20_profile_generate_artifact(LassoProfile *profile, int part)
{
	lasso_assign_new_string(profile->private_data->artifact,
			lasso_saml20_profile_build_artifact(LASSO_PROVIDER(profile->server)));
	if (part == 0) {
		lasso_assign_new_string(profile->private_data->artifact_message, lasso_node_dump(profile->request));
	} else if (part == 1) {
		lasso_assign_new_string(profile->private_data->artifact_message, lasso_node_dump(profile->response));
	} else {
		/* XXX: RequestDenied here? */
	}

	return profile->private_data->artifact;
}


static char*
lasso_saml20_profile_build_artifact(LassoProvider *provider)
{
	xmlSecByte samlArt[44], *b64_samlArt;
	char *source_succinct_id;
	char *ret;

	source_succinct_id = lasso_sha1(provider->ProviderID);

	/* Artifact Format is described in saml-bindings-2.0-os, 3.6.4.2. */
	memcpy(samlArt, "\000\004", 2); /* type code */
	memcpy(samlArt+2, "\000\000", 2); /* XXX: Endpoint index */
	memcpy(samlArt+4, source_succinct_id, 20);
	lasso_build_random_sequence((char*)samlArt+24, 20);

	xmlFree(source_succinct_id);
	b64_samlArt = xmlSecBase64Encode(samlArt, 44, 0);

	ret = g_strdup((char*)b64_samlArt);
	xmlFree(b64_samlArt);

	return ret;
}

int
lasso_saml20_profile_set_response_status(LassoProfile *profile,
		const char *code1, const char *code2)
{
	LassoSamlp2StatusResponse *status_response = NULL;
	LassoSamlp2Status *status = NULL;
	LassoSamlp2StatusCode *status_code1 = NULL;
	LassoSamlp2StatusCode *status_code2 = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_null_param(code1);
	lasso_extract_node_or_fail(status_response, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_RESPONSE);

	if (! LASSO_IS_SAMLP2_STATUS(status_response->Status)) {
		lasso_assign_new_gobject(status_response->Status,
				(LassoSamlp2Status*)lasso_samlp2_status_new());
	}
	status = status_response->Status;
	if (! LASSO_IS_SAMLP2_STATUS_CODE(status->StatusCode)) {
		lasso_assign_new_gobject(status->StatusCode,
				(LassoSamlp2StatusCode*)lasso_samlp2_status_code_new());
	}
	status_code1 = status->StatusCode;
	lasso_assign_string(status_code1->Value, code1);

	if (code2) {
		if (! LASSO_IS_SAMLP2_STATUS_CODE(status_code1->StatusCode)) {
			lasso_assign_new_gobject(status_code1->StatusCode,
					(LassoSamlp2StatusCode*)lasso_samlp2_status_code_new());
		}
		status_code2 = status_code1->StatusCode;
		lasso_assign_string(status_code2->Value, code2);
	}

cleanup:
	return rc;
}

int
lasso_saml20_profile_init_artifact_resolve(LassoProfile *profile,
		const char *msg, LassoHttpMethod method)
{
	char **query_fields;
	char *artifact_b64 = NULL;
	xmlChar *provider_succinct_id_b64 = NULL;
	char *provider_succinct_id[21];
	char artifact[45];
	LassoSamlp2RequestAbstract *request = NULL;
	int i = 0;

	if (method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
		query_fields = urlencoded_to_strings(msg);
		for (i=0; query_fields[i]; i++) {
			if (strncmp((char*)query_fields[i], "SAMLart=", 8) == 0) {
				lasso_assign_string(artifact_b64, query_fields[i]+8);
			}
			xmlFree(query_fields[i]);
		}
		lasso_release(query_fields);
		if (artifact_b64 == NULL) {
			return LASSO_PROFILE_ERROR_MISSING_ARTIFACT;
		}
	} else if (method == LASSO_HTTP_METHOD_ARTIFACT_POST) {
		artifact_b64 = g_strdup(msg);
	} else {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	i = xmlSecBase64Decode((xmlChar*)artifact_b64, (xmlChar*)artifact, 45);
	if (i < 0 || i > 44) {
		lasso_release_string(artifact_b64);
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}

	if (artifact[0] != 0 || artifact[1] != 4) { /* wrong type code */
		lasso_release_string(artifact_b64);
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}

	/* XXX: index endpoint */

	memcpy(provider_succinct_id, artifact+4, 20);
	provider_succinct_id[20] = 0;

	provider_succinct_id_b64 = xmlSecBase64Encode((xmlChar*)provider_succinct_id, 20, 0);

	lasso_assign_new_string(profile->remote_providerID, lasso_server_get_providerID_from_hash(
			profile->server, (char*)provider_succinct_id_b64));
	lasso_release_xml_string(provider_succinct_id_b64);
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	lasso_assign_new_gobject(profile->request, lasso_samlp2_artifact_resolve_new());
	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	lasso_assign_new_string(LASSO_SAMLP2_ARTIFACT_RESOLVE(request)->Artifact, artifact_b64);
	request->ID = lasso_build_unique_id(32);
	lasso_assign_string(request->Version, "2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	request->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (profile->server->certificate) {
		request->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		request->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	lasso_assign_new_string(profile->msg_relayState, lasso_get_relaystate_from_query(msg));

	return 0;
}

int
lasso_saml20_profile_process_artifact_resolve(LassoProfile *profile, const char *msg)
{
	LassoProvider *remote_provider;
	int rc;

	lasso_assign_new_gobject(profile->request, lasso_node_new_from_soap(msg));
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	if (! LASSO_IS_SAMLP2_ARTIFACT_RESOLVE(profile->request)) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	lasso_assign_string(profile->remote_providerID, LASSO_SAMLP2_REQUEST_ABSTRACT(
			profile->request)->Issuer->content);
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);

	rc = lasso_provider_verify_signature(remote_provider, msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);

	lasso_assign_string(profile->private_data->artifact,
			LASSO_SAMLP2_ARTIFACT_RESOLVE(profile->request)->Artifact);

	return rc;
}

int
lasso_saml20_profile_build_artifact_response(LassoProfile *profile)
{
	LassoSamlp2StatusResponse *response;
	LassoNode *resp = NULL;


	response = LASSO_SAMLP2_STATUS_RESPONSE(lasso_samlp2_artifact_response_new());
	if (profile->private_data->artifact_message) {
		resp = lasso_node_new_from_dump(profile->private_data->artifact_message);
		lasso_assign_new_gobject(LASSO_SAMLP2_ARTIFACT_RESPONSE(response)->any, resp);
	}
	response->ID = lasso_build_unique_id(32);
	lasso_assign_string(response->Version, "2.0");
	response->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	response->IssueInstant = lasso_get_current_time();
	lasso_assign_string(response->InResponseTo, LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	response->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (profile->server->certificate) {
		response->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		response->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	lasso_assign_string(response->private_key_file, profile->server->private_key);
	lasso_assign_string(response->certificate_file, profile->server->certificate);
	lasso_assign_new_gobject(profile->response, LASSO_NODE(response));

	if (resp == NULL) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUESTER, NULL);
	} else {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_SUCCESS, NULL);
	}
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(profile->response));
	return 0;
}

int
lasso_saml20_profile_process_artifact_response(LassoProfile *profile, const char *msg)
{
	LassoNode *response;
	LassoSamlp2ArtifactResponse *artifact_response;

	/* XXX: handle errors properly */

	response = lasso_node_new_from_soap(msg);
	if (!LASSO_IS_SAMLP2_ARTIFACT_RESPONSE(response)) {
		lasso_assign_new_gobject(profile->response, lasso_samlp2_response_new());
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}
	artifact_response = LASSO_SAMLP2_ARTIFACT_RESPONSE(response);

	if (artifact_response->any == NULL) {
		lasso_assign_new_gobject(profile->response, lasso_samlp2_response_new());
		return LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}
	lasso_assign_gobject(profile->response, artifact_response->any);
	lasso_release_gobject(response);

	return 0;
}

/**
 * lasso_saml20_profile_is_saml_query:
 * @query: HTTP query string
 *
 * Tests the query string to know if the URL is called as the result of a
 * SAML redirect (action initiated elsewhere) or not.
 *
 * Return value: TRUE if SAML query, FALSE otherwise
 **/
gboolean
lasso_profile_is_saml_query(const gchar *query)
{
	gchar *parameters[] = {
		"SAMLRequest=", "SAMLResponse=", "SAMLart=", NULL };
	gint i;

	g_return_val_if_fail(query, FALSE);
	for (i=0; parameters[i]; i++) {
		if (strstr(query, parameters[i]))
			return TRUE;
	}

	return FALSE;
}


static void
lasso_saml20_profile_set_session_from_dump_decrypt(
		LassoSaml2Assertion *assertion, G_GNUC_UNUSED gpointer data)
{
	if (LASSO_IS_SAML2_ASSERTION(assertion) == FALSE) {
		return;
	}

	if (assertion->Subject != NULL && assertion->Subject->EncryptedID != NULL) {
		lasso_assign_gobject(assertion->Subject->NameID,
			assertion->Subject->EncryptedID->original_data);
		lasso_release_gobject(assertion->Subject->EncryptedID);
	}
}

gint
lasso_saml20_profile_set_session_from_dump(LassoProfile *profile)
{
	GList *assertions = NULL;

	lasso_bad_param(PROFILE, profile);

	if (lasso_session_count_assertions(profile->session) > 0) {
		assertions = lasso_session_get_assertions(profile->session, NULL);

		g_list_foreach(assertions,
				(GFunc)lasso_saml20_profile_set_session_from_dump_decrypt,
				NULL);
		lasso_release_list(assertions);
	}

	return 0;
}

/**
 * lasso_saml20_profile_process_name_identifier_decryption:
 * @profile: the #LassoProfile object
 * @name_id: the field containing the #LassoSaml2NameID object
 * @encrypted_id: the field containing an encrypted #LassoSaml2NameID as a #LassoSaml2EncryptedElement
 *
 * Place content of the NameID in the profile nameIdentifier field, if no NameID is present but an
 * EncryptedElement is, then decrypt it, store it in place of the name_id field and in the
 * nameIdentifier field of the profile.
 *
 * Return value: 0 if successful,
 * LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER if no NameID can be found,
 * LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY if an encryption element is present but no no
 * decryption key.
 */
gint
lasso_saml20_profile_process_name_identifier_decryption(LassoProfile *profile,
		LassoSaml2NameID **name_id,
		LassoSaml2EncryptedElement **encrypted_id)
{
	xmlSecKey *encryption_private_key = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_null_param(name_id);
	lasso_null_param(encrypted_id);

	if (*name_id == NULL && *encrypted_id != NULL) {
		encryption_private_key = profile->server->private_data->encryption_private_key;
		if (! LASSO_IS_SAML2_ENCRYPTED_ELEMENT(*encrypted_id)) {
			return LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER;
		}
		if (encrypted_id != NULL && encryption_private_key == NULL) {
			return LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY;
		}
		rc = lasso_saml2_encrypted_element_decrypt(*encrypted_id, encryption_private_key,
				&profile->nameIdentifier);
		if (rc)
			goto cleanup;
		if (! LASSO_IS_SAML2_NAME_ID(profile->nameIdentifier)) {
			rc = LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER;
			goto cleanup;
		}

		// swap the node contents
		lasso_assign_gobject(*name_id, LASSO_SAML2_NAME_ID(profile->nameIdentifier));
		lasso_release_gobject(*encrypted_id);
	} else {
		lasso_assign_gobject(profile->nameIdentifier, (LassoNode*)*name_id);
	}
cleanup:
	return rc;
}

/**
 * lasso_saml20_profile_process_any_request:
 * @profile: a #LassoProfile object
 * @request_node: a #LassoNode object which will be initialized with the content of @request_msg
 * @request_msg: a string containing the request message as a SOAP XML message, a query string of
 * the content of SAMLRequest POST field.
 *
 * Parse a request message, initialize the given node object with it, try to extract basic SAML
 * profile information like the remote_provider_id or the name_id and validate the signature.
 *
 * Signature validation status is accessible in profile->signature_status, beware that if signature
 * validation fails no error code will be returned, you must explicitely verify the
 * profile->signature_status code.
 *
 * Return value: 0 if parsing is successfull (even if signature validation fails), and error code
 * otherwise.
 */
int
lasso_saml20_profile_process_any_request(LassoProfile *profile,
		LassoNode *request_node,
		char *request_msg)
{
	int rc = 0;
	LassoSaml2NameID *name_id = NULL;
	LassoProvider *remote_provider = NULL;
	LassoSamlp2RequestAbstract *request_abstract = NULL;
	LassoMessageFormat format;
	xmlDoc *doc = NULL;
	xmlNode *content = NULL;

	lasso_bad_param(PROFILE, profile);

	/* reset signature_status */
	profile->signature_status = 0;
	format = lasso_node_init_from_message_with_format(request_node,
		request_msg, LASSO_MESSAGE_FORMAT_UNKNOWN, &doc, &content);
	if (format <= LASSO_MESSAGE_FORMAT_UNKNOWN) {
		rc = LASSO_PROFILE_ERROR_INVALID_MSG;
		goto cleanup;
	}
	switch (format) {
		case LASSO_MESSAGE_FORMAT_BASE64:
			profile->http_request_method = LASSO_HTTP_METHOD_POST;
			break;
		case LASSO_MESSAGE_FORMAT_SOAP:
			profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
			break;
		case LASSO_MESSAGE_FORMAT_QUERY:
			profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;
			break;
		default:
			rc = LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
			goto cleanup;
	}
	lasso_assign_gobject(profile->request, request_node);
	if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		lasso_assign_new_string(profile->msg_relayState,
			lasso_get_relaystate_from_query(request_msg));
	}

	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(name_id, request_abstract->Issuer, SAML2_NAME_ID,
			LASSO_PROFILE_ERROR_MISSING_ISSUER);
	lasso_assign_string(profile->remote_providerID, request_abstract->Issuer->content);

	rc = get_provider(profile, &remote_provider);
	goto_cleanup_if_fail(rc == 0);

	/* verify the signature at the request level */
	if (content && doc && format != LASSO_MESSAGE_FORMAT_QUERY) {
		profile->signature_status =
			lasso_provider_verify_saml_signature(remote_provider, content, doc);
	} else if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		profile->signature_status =
			lasso_provider_verify_query_signature(remote_provider, request_msg);
	} else {
		profile->signature_status = LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE;
	}

cleanup:

	lasso_release_doc(doc);
	return rc;
}


int
lasso_saml20_profile_process_soap_request(LassoProfile *profile,
		char *request_msg)
{
	int rc = 0;
	LassoSaml2NameID *issuer = NULL;
	LassoProvider *remote_provider = NULL;
	LassoSamlp2RequestAbstract *request_abstract = NULL;

	lasso_bad_param(PROFILE, profile);

	profile->signature_status = 0;
	lasso_assign_new_gobject(profile->request, lasso_node_new_from_soap(request_msg));
	profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(issuer, request_abstract->Issuer, SAML2_NAME_ID,
			LASSO_PROFILE_ERROR_MISSING_ISSUER);
	lasso_assign_string(profile->remote_providerID, issuer->content);

	rc = get_provider(profile, &remote_provider);
	goto_cleanup_if_fail(rc == 0);

	rc = profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);

cleanup:

	return rc;
}

int
lasso_saml20_init_request(LassoProfile *profile,
		char *remote_provider_id,
		gboolean first_in_session,
		LassoSamlp2RequestAbstract *request_abstract,
		LassoHttpMethod http_method,
		LassoMdProtocolType protocol_type)
{
	LassoIdentity *identity = NULL;
	LassoSession *session = NULL;
	LassoServer *server = NULL;
	LassoProvider *remote_provider = NULL;
	LassoSaml2NameID *name_id = NULL;
	char *remote_provider_id_auto = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(SAMLP2_REQUEST_ABSTRACT, request_abstract);
	if (http_method < LASSO_HTTP_METHOD_ANY || http_method >= LASSO_HTTP_METHOD_LAST) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid LassoHttpMethod argument");
		return LASSO_PARAM_ERROR_INVALID_VALUE;
	}

	/* verify identity and sessions */
	lasso_extract_node_or_fail(identity, profile->identity, IDENTITY,
			LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	lasso_extract_node_or_fail(session, profile->session, SESSION,
			LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);

	/* set remote provider Id */
	if (! remote_provider_id) {
		if (first_in_session) {
			remote_provider_id_auto = lasso_session_get_provider_index(session, 0);
		} else {
			remote_provider_id_auto = lasso_server_get_first_providerID(server);
		}
	}
	if (! remote_provider_id && ! remote_provider_id_auto) {
		rc = LASSO_PROFILE_ERROR_CANNOT_FIND_A_PROVIDER;
		goto cleanup;
	}
	if (remote_provider_id) {
		lasso_assign_string(profile->remote_providerID, remote_provider_id);
	} else {
		lasso_assign_new_string(profile->remote_providerID, remote_provider_id_auto);
	}
	rc = get_provider(profile, &remote_provider);
	if (rc)
		goto cleanup;
	/* set the name identifier */
	name_id = (LassoSaml2NameID*)lasso_profile_get_nameIdentifier(profile);
	if (! LASSO_IS_SAML2_NAME_ID(name_id)) {
		rc = LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND;
		goto cleanup;
	}
	lasso_assign_gobject(profile->nameIdentifier, (LassoNode*)name_id);

	/* verify that this provider supports the current http method */
	if (http_method == LASSO_HTTP_METHOD_ANY) {
		http_method = lasso_saml20_provider_get_first_http_method((LassoProvider*)server,
				remote_provider, protocol_type);
	}
	if (http_method == LASSO_HTTP_METHOD_NONE) {
		rc = LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		goto cleanup;
	}
	if (! lasso_saml20_provider_accept_http_method(
				(LassoProvider*)server,
				remote_provider,
				protocol_type,
				http_method,
				TRUE)) {
		rc = LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
	}
	profile->http_request_method = http_method;

	/* initialize request fields */
	lasso_assign_new_string(request_abstract->ID, lasso_build_unique_id(32));
	lasso_assign_string(request_abstract->Version, "2.0");
	lasso_assign_new_gobject(request_abstract->Issuer,
			LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
					LASSO_PROVIDER(profile->server)->ProviderID)));
	lasso_assign_new_string(request_abstract->IssueInstant, lasso_get_current_time());
	lasso_assign_gobject(profile->request, LASSO_NODE(request_abstract));

cleanup:
	return rc;
}

static int
lasso_saml20_profile_build_post_request_msg(LassoProfile *profile,
		LassoProvider *provider, char *service)
{
	int rc = 0;
	LassoSamlp2RequestAbstract *request_abstract;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(PROVIDER, provider);
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);

	lasso_assign_new_string(profile->msg_url, get_response_url(provider, service, "HTTP-POST"));
	if (! profile->msg_url) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}
	lasso_assign_new_string(profile->msg_body,
			lasso_node_export_to_base64(LASSO_NODE(request_abstract)));
	if (! profile->msg_body) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}
cleanup:
	return rc;
}

static int
lasso_saml20_profile_build_soap_request_msg(LassoProfile *profile, LassoProvider *provider,
		char *service)
{
	int rc = 0;
	char *url = NULL;
	LassoSamlp2RequestAbstract *request_abstract;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(PROVIDER, provider);
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);

	url = get_url(provider, service, "SOAP");
	if (! url) {
		rc = critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		goto cleanup;
	}
	lasso_assign_new_string(profile->msg_body,
			lasso_node_export_to_soap(LASSO_NODE(request_abstract)));
	lasso_transfer_string(profile->msg_url, url);

	if (! profile->msg_body) {
		return LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED;
	}

cleanup:
	lasso_release_string(url);
	return rc;
}

static int
lasso_saml20_profile_build_redirect_request_msg(LassoProfile *profile, LassoProvider *provider,
		char *service, gboolean no_signature)
{
	int rc = 0;
	char *url = NULL;
	LassoSamlp2RequestAbstract *request_abstract;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(PROVIDER, provider);
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	if (no_signature)
		request_abstract->sign_type = LASSO_SIGNATURE_TYPE_NONE;
	url = get_url(provider, service, "HTTP-Redirect");
	rc = lasso_saml20_profile_build_http_redirect(profile,
			profile->request,
			lasso_flag_add_signature,
			url);
	if (rc)
		goto cleanup;

cleanup:
	lasso_release_string(url);
	return rc;

}

int
lasso_saml20_profile_setup_request_signing(LassoProfile *profile)
{
	LassoSamlp2RequestAbstract *request_abstract = NULL;
	LassoServer *server = NULL;
	int rc = 0;

	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);

	request_abstract->sign_method = server->signature_method;
	request_abstract->sign_type = server->certificate ? LASSO_SIGNATURE_TYPE_WITHX509 :
		LASSO_SIGNATURE_TYPE_SIMPLE;
	lasso_assign_string(request_abstract->private_key_file, server->private_key);
	lasso_assign_string(request_abstract->certificate_file, server->certificate);

cleanup:
	return rc;
}

int
lasso_saml20_profile_build_request_msg(LassoProfile *profile, char *service, gboolean no_signature)
{
	LassoProvider *provider;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);

	lasso_profile_clean_msg_info(profile);
	rc = get_provider(profile, &provider);
	if (rc)
		goto cleanup;

	rc = lasso_saml20_profile_setup_request_signing(profile);
	if (rc)
		goto cleanup;

	switch (profile->http_request_method) {
		case LASSO_HTTP_METHOD_SOAP:
			rc = lasso_saml20_profile_build_soap_request_msg(profile, provider,
					service);
			break;
		case LASSO_HTTP_METHOD_POST:
			rc = lasso_saml20_profile_build_post_request_msg(profile, provider,
					service);
			break;
		case LASSO_HTTP_METHOD_REDIRECT:
			rc = lasso_saml20_profile_build_redirect_request_msg(profile, provider,
					service, no_signature);
			break;
		case LASSO_HTTP_METHOD_ARTIFACT_GET:
		case LASSO_HTTP_METHOD_ARTIFACT_POST:
			rc = LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
			break;
		default:
			rc = LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
			break;
	}

cleanup:
	return rc;

}

int
lasso_saml20_profile_init_response(LassoProfile *profile, const char *status_code1, const char *status_code2)
{
	LassoSamlp2StatusResponse *status_response = NULL;
	LassoSamlp2RequestAbstract *request_abstract = NULL;
	LassoServer *server = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_extract_node_or_fail(status_response, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_RESPONSE);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	lasso_assign_new_string(status_response->ID, lasso_build_unique_id(32));
	lasso_assign_string(status_response->Version, "2.0");
	lasso_assign_new_gobject(status_response->Issuer,
			LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
					server->parent.ProviderID)));
	lasso_assign_new_string(status_response->IssueInstant, lasso_get_current_time());
	lasso_assign_string(status_response->InResponseTo, request_abstract->ID);
	if (status_code1)
		lasso_saml20_profile_set_response_status(profile,
				status_code1, status_code2);

cleanup:
	return rc;
}

int
lasso_saml20_profile_validate_request(LassoProfile *profile, gboolean needs_identity,
		LassoSamlp2StatusResponse *status_response, LassoProvider **provider_out)
{
	int rc = 0;
	LassoSamlp2RequestAbstract *request_abstract = NULL;
	LassoSaml2NameID *issuer = NULL;
	LassoIdentity *identity = NULL;
	LassoProvider *provider = NULL;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(SAMLP2_STATUS_RESPONSE, status_response);
	/* verify request presence */
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);
	/* look for identity object */
	if (needs_identity) {
		lasso_extract_node_or_fail(identity, profile->identity, IDENTITY,
				LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	/* extract provider */
	lasso_extract_node_or_fail(issuer, request_abstract->Issuer, SAML2_NAME_ID,
			LASSO_PROFILE_ERROR_MISSING_ISSUER);
	lasso_assign_string(profile->remote_providerID, issuer->content);
	rc = get_provider(profile, &provider);
	if (rc)
		goto cleanup;

	/* init the response */
	lasso_assign_gobject(profile->response, &status_response->parent);
	lasso_saml20_profile_init_response(profile, LASSO_SAML2_STATUS_CODE_SUCCESS, NULL);

	if (profile->signature_status) {
		message(G_LOG_LEVEL_WARNING, "Request signature is invalid");
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUESTER,
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
		return profile->signature_status;
	}

cleanup:
	if (provider && provider_out)
		*provider_out = provider;
	return rc;

}

static int
lasso_saml20_profile_setup_response_signing(LassoProfile *profile)
{
	LassoSamlp2StatusResponse *response_abstract = NULL;
	LassoServer *server = NULL;
	int rc = 0;

	lasso_extract_node_or_fail(response_abstract, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(server, profile->server, SERVER, LASSO_PROFILE_ERROR_MISSING_SERVER);

	response_abstract->sign_method = server->signature_method;
	response_abstract->sign_type = server->certificate ? LASSO_SIGNATURE_TYPE_WITHX509 :
		LASSO_SIGNATURE_TYPE_SIMPLE;
	lasso_assign_string(response_abstract->private_key_file, server->private_key);
	lasso_assign_string(response_abstract->certificate_file, server->certificate);

cleanup:

	return rc;

}

static int
lasso_saml20_profile_build_post_response(LassoProfile *profile, LassoProvider *provider, char *service)
{
	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(PROVIDER, provider);

	lasso_assign_new_string(profile->msg_url, get_response_url(provider, service, "HTTP-POST"));
	if (! profile->msg_url) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_base64(profile->request));
	if (! profile->msg_body) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}
	return 0;
}

static int
lasso_saml20_profile_build_redirect_response(LassoProfile *profile, LassoProvider *provider, char
		*service, gboolean no_signature)
{
	LassoSamlp2StatusResponse *status_response = NULL;
	char *url = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_null_param(service);

	lasso_extract_node_or_fail(status_response, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_RESPONSE);
	if (no_signature) // for authn response
		status_response->sign_type = LASSO_SIGNATURE_TYPE_NONE;
	// get url
	url = get_response_url(provider, service, "HTTP-Redirect");
	rc = lasso_saml20_profile_build_http_redirect(profile,
			profile->response,
			lasso_flag_add_signature,
			url);

cleanup:
	lasso_release_string(url);
	return rc;
}

static int
lasso_saml20_profile_build_soap_response(LassoProfile *profile)
{
	lasso_bad_param(PROFILE, profile);

	lasso_release_string(profile->msg_url);
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(profile->response));

	if (! profile->msg_body) {
		return LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED;
	}

	return 0;
}

/**
 * lasso_saml20_profile_export_to_query:
 * @profile: a #LassoProfile
 * @request_or_response: 0 to encode the request, 1 to encode the response
 * @sign: TRUE if query must signed, FALSE otherwise
 *
 * Create a query following the DEFLATE encoding of the SAML 2.0 HTTP
 * Redirect binding.
 *
 * Return value: a newly allocated string containing the query string if successfull, NULL otherwise.
 */
static int
lasso_saml20_profile_export_to_query(LassoProfile *profile, LassoNode *msg, int sign, char **query) {
	char *unsigned_query = NULL;
	char *result = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(NODE, msg);

	unsigned_query = lasso_node_build_query(msg);
	if (profile->msg_relayState) {
		unsigned_query = lasso_url_add_parameters(unsigned_query, 1, "RelayState", profile->msg_relayState, NULL);

		if (strlen(profile->msg_relayState) > 80) {
			g_warning("Encoded a RelayState of more than 80 bytes, see #3.4.3 of"
					" saml-bindings-2.0-os");
		}
	}
	if (sign && lasso_flag_add_signature) {
		LassoServer *server = profile->server;
		goto_cleanup_if_fail_with_rc (LASSO_IS_SERVER(server),
				LASSO_PROFILE_ERROR_MISSING_SERVER);
		goto_cleanup_if_fail_with_rc (
				profile->server->signature_method != LASSO_SIGNATURE_TYPE_NONE &&
				profile->server->private_key,
				LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED);
		result = lasso_query_sign(unsigned_query, profile->server->signature_method,
				profile->server->private_key);
		lasso_transfer_string(*query, result);
	} else {
		lasso_transfer_string(*query, unsigned_query);
	}
cleanup:
	lasso_release_string(unsigned_query);
	lasso_release_string(result);
	return rc;
}

static void
remove_signature(LassoNode *node) {
	LassoNodeClass *klass;

	if (node == NULL)
		return;

	klass = LASSO_NODE_GET_CLASS(node);
	/* follow the class parenting chain */
	while (klass && LASSO_IS_NODE_CLASS(klass)) {
		if (klass && klass->node_data && klass->node_data->sign_type_offset != 0) {
			G_STRUCT_MEMBER(LassoSignatureType, node, klass->node_data->sign_type_offset) =
				LASSO_SIGNATURE_TYPE_NONE;
		}
		klass = g_type_class_peek_parent(klass);
	}
}

static void
remove_all_signatures(LassoNode *node) {
	LassoNodeClass *klass;
	struct XmlSnippet *snippet;

	if (node == NULL)
		return;
	klass = LASSO_NODE_GET_CLASS(node);
	remove_signature(node);
	snippet = klass->node_data->snippets;
	while (snippet && snippet->name) {
		SnippetType type;
		void *value;
		GList *elem;

		value = G_STRUCT_MEMBER(void*, node, snippet->offset);
		type = snippet->type & 0xff;
		switch (type) {
			case SNIPPET_NODE:
			case SNIPPET_NODE_IN_CHILD:
				remove_all_signatures(LASSO_NODE(value));
				break;
			case SNIPPET_LIST_NODES:
				elem = (GList*)value;
				while (elem) {
					remove_all_signatures(LASSO_NODE(elem->data));
					elem = g_list_next(elem);
				}
				break;
			default:
				break;
		}
		snippet++;
	}
}

/**
 * lasso_saml20_profile_build_http_redirect:
 * @profile: a #LassoProfile object
 * @msg: a #LassoNode object representing a SAML 2.0 message
 * @must_sign: wheter to sign the query message using query signatures
 * @url: the URL where the query is targeted
 *
 * Build an HTTP URL with a query-string following the SAML 2.0 HTTP-Redirect binding rules,
 * eventually sign it. Any signature at the message level is removed.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_saml20_profile_build_http_redirect(LassoProfile *profile,
	LassoNode *msg,
	gboolean must_sign,
	const char *url)
{
	char *query = NULL;
	int rc = 0;

	if (url == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}
	/* remove XML signature */
	remove_signature(msg);
	/* No signature on the XML message */
	rc = lasso_saml20_profile_export_to_query(profile, msg, must_sign, &query);
	if (rc)
		return rc;

	lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
	lasso_release(profile->msg_body);
	lasso_release(query);

	return 0;
}

int
lasso_saml20_profile_build_response(LassoProfile *profile, char *service, gboolean no_signature,
		LassoHttpMethod method)
{
	LassoProvider *provider;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);

	lasso_profile_clean_msg_info(profile);
	rc = get_provider(profile, &provider);
	if (rc)
		goto cleanup;

	rc = lasso_saml20_profile_setup_response_signing(profile);
	if (rc) goto cleanup;
	switch (method) {
		case LASSO_HTTP_METHOD_POST:
			rc = lasso_saml20_profile_build_post_response(profile, provider, service);
			break;
		case LASSO_HTTP_METHOD_REDIRECT:
			rc = lasso_saml20_profile_build_redirect_response(profile, provider,
					service, no_signature);
			break;
		case LASSO_HTTP_METHOD_SOAP:
			rc = lasso_saml20_profile_build_soap_response(profile);
			break;
		default:
			rc= LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
			break;
	}

cleanup:
	return rc;
}

/**
 * lasso_saml20_profile_process_any_response:
 * @profile: the SAML 2.0 #LassoProfile object
 * @status_response: the prototype for the response object
 * @response_msg: the content of the response message
 *
 * Generic method for SAML 2.0 protocol message handling.
 *
 * It tries to validate a signature on the response msg, the result of this operation is kept inside
 * profile->signature_status. Use it afterward in your specific profile. Beware that it does not
 * return an error code if signature validation failed. It let's specific profile accept unsigned
 * messages.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_saml20_profile_process_any_response(LassoProfile *profile,
		LassoSamlp2StatusResponse *status_response,
		char *response_msg)
{
	int rc = 0;

	LassoSaml2NameID *name_id = NULL;
	LassoProvider *remote_provider = NULL;
	LassoServer *server = NULL;
	LassoSamlp2StatusResponse *response_abstract = NULL;
	LassoSamlp2Status *status = NULL;
	LassoSamlp2StatusCode *status_code1 = NULL;
	LassoSamlp2StatusCode *status_code2 = NULL;
	LassoMessageFormat format;

	xmlDoc *doc = NULL;
	xmlNode *content = NULL;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(SAMLP2_STATUS_RESPONSE, status_response);

	/* reset signature_status */
	profile->signature_status = 0;
	format = lasso_node_init_from_message_with_format((LassoNode*)status_response,
		response_msg, LASSO_MESSAGE_FORMAT_UNKNOWN, &doc, &content);
	if (format <= LASSO_MESSAGE_FORMAT_UNKNOWN) {
		rc = LASSO_PROFILE_ERROR_INVALID_MSG;
		goto cleanup;
	}
	lasso_assign_gobject(profile->response, (LassoNode*)status_response);
	lasso_extract_node_or_fail(response_abstract, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	lasso_extract_node_or_fail(name_id, response_abstract->Issuer, SAML2_NAME_ID,
			LASSO_PROFILE_ERROR_MISSING_ISSUER);
	lasso_assign_string(profile->remote_providerID, response_abstract->Issuer->content);

	remote_provider = lasso_server_get_provider(server, profile->remote_providerID);
	if (remote_provider == NULL) {
		rc = LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
		goto cleanup;
	}

	/* verify the signature at the request level */
	if (content && doc && format != LASSO_MESSAGE_FORMAT_QUERY) {
		profile->signature_status =
			lasso_provider_verify_saml_signature(remote_provider, content, doc);
	} else if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		profile->signature_status =
			lasso_provider_verify_query_signature(remote_provider, response_msg);
	} else {
		profile->signature_status = LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE;
	}

	/* verify status code */
	lasso_extract_node_or_fail(status, status_response->Status, SAMLP2_STATUS,
			LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	lasso_extract_node_or_fail(status_code1, status->StatusCode, SAMLP2_STATUS_CODE,
			LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	if (! status_code1->Value) {
		rc = LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
		goto cleanup;
	}
	if (status_code1->StatusCode && status_code1->StatusCode->Value)
	{
		status_code2 = status_code1->StatusCode;
	}

	if (strcmp(status_code1->Value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "Status Code is not Success on a SAML 2.0 response:"
				"1st leve «%s» 2nd leve «%s»", status_code1->Value, status_code2 ?
				status_code2->Value : "");
		rc = LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;
		goto cleanup;
	}

cleanup:
	lasso_release_doc(doc);
	if (rc == LASSO_PROFILE_ERROR_MISSING_STATUS_CODE) {
		message(G_LOG_LEVEL_CRITICAL,
			"Status Code is missing in a SAML 2.0 protocol response");
	}
	return rc;
}

/**
 * lasso_saml20_profile_process_soap_response:
 *
 * Generic method for processing SAML 2.0 protocol message as a SOAP response.
 *
 * Return value: 0 if successful; an error code otherwise.
 */
int
lasso_saml20_profile_process_soap_response(LassoProfile *profile,
		char *response_msg)
{
	int rc = 0;
	LassoSaml2NameID *issuer = NULL;
	LassoProvider *remote_provider = NULL;
	LassoServer *server = NULL;
	LassoSamlp2StatusResponse *response_abstract = NULL;

	lasso_bad_param(PROFILE, profile);
	lasso_null_param(response_msg);

	profile->signature_status = 0;
	lasso_assign_new_gobject(profile->response, lasso_node_new_from_soap(response_msg));
	lasso_extract_node_or_fail(response_abstract, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	lasso_extract_node_or_fail(issuer, response_abstract->Issuer, SAML2_NAME_ID,
			LASSO_PROFILE_ERROR_MISSING_ISSUER);
	lasso_assign_string(profile->remote_providerID, issuer->content);

	remote_provider = lasso_server_get_provider(server, profile->remote_providerID);
	if (remote_provider == NULL) {
		rc = LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
		goto cleanup;
	}

	rc = profile->signature_status = lasso_provider_verify_signature(
			remote_provider, response_msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);

cleanup:
	return rc;
}

gint
lasso_saml20_build_http_redirect_query_simple(LassoProfile *profile,
		LassoNode *msg,
		gboolean must_sign,
		const char *profile_name,
		gboolean is_response)
{
	char *idx = NULL;
	char *url = NULL;
	LassoProvider *remote_provider = NULL;
	int rc = 0;


	goto_cleanup_if_fail_with_rc(profile->remote_providerID != NULL,
			LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	remote_provider = lasso_server_get_provider(profile->server,
				profile->remote_providerID);
	goto_cleanup_if_fail_with_rc(LASSO_IS_PROVIDER(remote_provider),
			LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	if (is_response) {
		idx = g_strdup_printf("%s HTTP-Redirect ResponseLocation", profile_name);
		url = lasso_provider_get_metadata_one(remote_provider, idx);
		lasso_release(idx);
	}
	if (url == NULL) {
		idx = g_strdup_printf("%s HTTP-Redirect", profile_name);
		url = lasso_provider_get_metadata_one(remote_provider, idx);
		lasso_release(idx);
	}
	/* remove signature at the message level */
	rc = lasso_saml20_profile_build_http_redirect(profile, msg, must_sign, url);
cleanup:
	lasso_release(url);
	return rc;
}
