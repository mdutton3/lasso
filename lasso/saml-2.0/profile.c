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

#include "../xml/private.h"
#include <xmlsec/base64.h>

#include "../utils.h"
#include "providerprivate.h"
#include "profileprivate.h"
#include "profile.h"
#include "provider.h"

#include "../id-ff/providerprivate.h"
#include "../id-ff/profile.h"
#include "../id-ff/profileprivate.h"
#include "../id-ff/serverprivate.h"
#include "../id-ff/sessionprivate.h"
#include "../id-ff/login.h"

#include "../xml/private.h"
#include "../xml/soap-1.1/soap_envelope.h"
#include "../xml/saml-2.0/samlp2_request_abstract.h"
#include "../xml/saml-2.0/samlp2_artifact_resolve.h"
#include "../xml/saml-2.0/samlp2_artifact_response.h"
#include "../xml/saml-2.0/samlp2_authn_request.h"
#include "../xml/saml-2.0/samlp2_name_id_mapping_response.h"
#include "../xml/saml-2.0/samlp2_status_response.h"
#include "../xml/saml-2.0/samlp2_response.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/saml2_xsd.h"
#include "../xml/soap-1.1/soap_envelope.h"
#include "../xml/misc_text_node.h"
#include "../utils.h"
#include "../debug.h"



static char* lasso_saml20_profile_build_artifact(LassoProvider *provider);
static int lasso_saml20_profile_export_to_query(LassoProfile *profile, LassoNode *msg, char **query,
		LassoSignatureContext context);
static gint lasso_profile_saml20_build_artifact_get_request_msg(LassoProfile *profile,
		const char *service);
static gint lasso_profile_saml20_build_artifact_post_request_msg(LassoProfile *profile,
		const char *service);
static gint lasso_profile_saml20_build_artifact_get_response_msg(LassoProfile *profile,
		const char *service);
static gint lasso_profile_saml20_build_artifact_post_response_msg(LassoProfile *profile,
		const char *service);
static char* lasso_saml20_profile_generate_artifact(LassoProfile *profile, int part);

#define check_msg_body \
	if (! profile->msg_body) { \
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED); \
	}

/*
 * Helper functions
 */
static int
get_provider(LassoProfile *profile, LassoProvider **provider_out)
{
	LassoProvider *provider;
	LassoServer *server;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);

	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	provider = lasso_server_get_provider(server, profile->remote_providerID);
	if (! provider) {
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
	}

	*provider_out = provider;
cleanup:
	return rc;
}

static char *
get_url(LassoProvider *provider, const char *service, const char *binding)
{
	char *meta;
	char *result;

	meta = g_strdup_printf("%s %s", service, binding);
	result = lasso_provider_get_metadata_one(provider, meta);
	lasso_release_string(meta);
	return result;
}

static char *
get_response_url(LassoProvider *provider, const char *service, const char *binding)
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

static const char*
http_method_to_binding(LassoHttpMethod method) {
	switch (method) {
		case LASSO_HTTP_METHOD_POST:
			return "HTTP-POST";
		case LASSO_HTTP_METHOD_REDIRECT:
			return "HTTP-Redirect";
		case LASSO_HTTP_METHOD_SOAP:
			return "SOAP";
		case LASSO_HTTP_METHOD_ARTIFACT_GET:
		case LASSO_HTTP_METHOD_ARTIFACT_POST:
			return "HTTP-Artifact";
		case LASSO_HTTP_METHOD_PAOS:
			return "PAOS";
		default:
			return "";
	}
}

/*
 * Artifact Handling functions
 */

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
static char*
lasso_saml20_profile_generate_artifact(LassoProfile *profile, int part)
{
	LassoNode *what = NULL;
	lasso_assign_new_string(profile->private_data->artifact,
			lasso_saml20_profile_build_artifact(&profile->server->parent));
	if (part == 0) {
		what = profile->request;
	} else if (part == 1) {
		what = profile->response;
	} else {
		/* XXX: RequestDenied here? */
	}
	/* Remove signature at the response level, if needed if will be on the ArtifactResponse */
	lasso_node_remove_signature(what);
	/* Keep an XML copy of the response for later retrieval */
	lasso_assign_new_string(profile->private_data->artifact_message,
			lasso_node_export_to_xml(what));

	return profile->private_data->artifact;
}


static char*
lasso_saml20_profile_build_artifact(LassoProvider *provider)
{
	xmlSecByte samlArt[44], *b64_samlArt = NULL;
	char *source_succinct_id = NULL;
	char *ret = NULL;
	unsigned short index;

	source_succinct_id = lasso_sha1(provider->ProviderID);
	/* XXX: unchecked return value*/
	goto_cleanup_if_fail(lasso_saml20_provider_get_artifact_resolution_service_index(provider,
				&index) == 0);
	/* Artifact Format is described in saml-bindings-2.0-os, 3.6.4.2. */
	memcpy(samlArt, "\000\004", 2); /* type code */
	samlArt[2] = 0xFF & (index >> 8);
	samlArt[3] = 0xFF & index;
	memcpy(samlArt+4, source_succinct_id, 20);
	lasso_build_random_sequence((char*)samlArt+24, 20);

	b64_samlArt = xmlSecBase64Encode(samlArt, 44, 0);

	ret = g_strdup((char*)b64_samlArt);
cleanup:
	if (ret == NULL) {
		warning("Unable to find an artifact resolution service for entity id %s with %d",
				provider->ProviderID, provider->role);
	}
	lasso_release_string(source_succinct_id);
	lasso_release_xml_string(b64_samlArt);

	return ret;
}

/*
 * this function factorize all case for producing SAML artifact messages
 */
static gint
lasso_profile_saml20_build_artifact_msg(LassoProfile *profile,
		const char *url, int request_or_response, int get_or_post)
{
	char *artifact = lasso_saml20_profile_generate_artifact(profile, request_or_response);

	if (artifact == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
	}
	/* hack... */
	if (LASSO_IS_LOGIN(profile)) {
		LassoLogin *login = (LassoLogin*)profile;
		lasso_assign_string(login->assertionArtifact, artifact);
	}

	if (get_or_post == 0) {
		char *query;
		if (profile->msg_relayState) {
			query = lasso_url_add_parameters(NULL, 0, LASSO_SAML2_FIELD_ARTIFACT, artifact, "RelayState",
								profile->msg_relayState, NULL);
		} else {
			query = lasso_url_add_parameters(NULL, 0, LASSO_SAML2_FIELD_ARTIFACT, artifact, NULL);
		}
		lasso_assign_new_string(profile->msg_url,
			lasso_concat_url_query(url, query));
		lasso_release_string(query);
	} else {
		lasso_assign_string(profile->msg_url, url);
		lasso_assign_string(profile->msg_body, artifact);
	}
	return 0;
}

enum {
 REQUEST = 0,
 RESPONSE = 1,
 GET = 0,
 POST = 1
};

static gint
lasso_profile_saml20_build_artifact_get_request_msg(LassoProfile *profile, const char *url)
{
	return lasso_profile_saml20_build_artifact_msg(profile, url, REQUEST, GET);
}

static gint
lasso_profile_saml20_build_artifact_post_request_msg(LassoProfile *profile, const char *url)
{
	return lasso_profile_saml20_build_artifact_msg(profile, url, REQUEST, POST);
}

static gint
lasso_profile_saml20_build_artifact_get_response_msg(LassoProfile *profile, const char *url)
{
	return lasso_profile_saml20_build_artifact_msg(profile, url, RESPONSE, GET);
}

static gint
lasso_profile_saml20_build_artifact_post_response_msg(LassoProfile *profile, const char *url)
{
	return lasso_profile_saml20_build_artifact_msg(profile, url, RESPONSE, POST);
}

int
lasso_saml20_profile_init_artifact_resolve(LassoProfile *profile,
		LassoProviderRole remote_provider_role, const char *msg, LassoHttpMethod method)
{
	char **query_fields;
	char *artifact_b64 = NULL;
	xmlChar *provider_succinct_id_b64 = NULL;
	char *provider_succinct_id[21];
	char artifact[45];
	LassoSamlp2RequestAbstract *request = NULL;
	LassoProvider *remote_provider = NULL;
	int i = 0;
	int rc = 0;
	unsigned short index_endpoint = 0;

	if (method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
		query_fields = urlencoded_to_strings(msg);
		for (i=0; query_fields[i]; i++) {
			if (strncmp((char*)query_fields[i], LASSO_SAML2_FIELD_ARTIFACT "=", 8) == 0) {
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

	memcpy(provider_succinct_id, artifact+4, 20);
	provider_succinct_id[20] = 0;

	provider_succinct_id_b64 = xmlSecBase64Encode((xmlChar*)provider_succinct_id, 20, 0);

	lasso_assign_new_string(profile->remote_providerID, lasso_server_get_providerID_from_hash(
			profile->server, (char*)provider_succinct_id_b64));
	lasso_release_xml_string(provider_succinct_id_b64);
	if (profile->remote_providerID == NULL) {
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
	}

	/* resolve the resolver url using the endpoint index in the artifact string */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	index_endpoint = (artifact[2] << 16) + artifact[3];
	lasso_assign_string(profile->msg_url, lasso_saml20_provider_get_endpoint_url(remote_provider,
			remote_provider_role,
			LASSO_SAML2_METADATA_ELEMENT_ARTIFACT_RESOLUTION_SERVICE, NULL, FALSE,
			FALSE, index_endpoint));
	if (! profile->msg_url) {
		debug("looking for index endpoint %d", index_endpoint);
		return LASSO_PROFILE_ERROR_ENDPOINT_INDEX_NOT_FOUND;
	}


	lasso_assign_new_gobject(profile->request, lasso_samlp2_artifact_resolve_new());
	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	lasso_assign_new_string(LASSO_SAMLP2_ARTIFACT_RESOLVE(request)->Artifact, artifact_b64);
	request->ID = lasso_build_unique_id(32);
	lasso_assign_string(request->Version, "2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	lasso_check_good_rc(lasso_profile_saml20_setup_message_signature(profile,
				(LassoNode*)request));

cleanup:
	return rc;
}

int
lasso_saml20_profile_process_artifact_resolve(LassoProfile *profile, const char *msg)
{
	LassoProvider *remote_provider;
	int rc = 0;
	LassoProfileSignatureVerifyHint sig_verify_hint;

	/* FIXME: parse only one time the message, reuse the parsed document for signature
	 * validation */
	lasso_assign_new_gobject(profile->request, lasso_node_new_from_soap(msg));
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	if (! LASSO_IS_SAMLP2_ARTIFACT_RESOLVE(profile->request)) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	lasso_assign_string(profile->private_data->artifact,
			LASSO_SAMLP2_ARTIFACT_RESOLVE(profile->request)->Artifact);

	sig_verify_hint = lasso_profile_get_signature_verify_hint(profile);

	lasso_assign_string(profile->remote_providerID, LASSO_SAMLP2_REQUEST_ABSTRACT(
			profile->request)->Issuer->content);
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);

	goto_cleanup_if_fail_with_rc(remote_provider, LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER);

	if (sig_verify_hint != LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE) {
		profile->signature_status = lasso_provider_verify_signature(remote_provider, msg, "ID",
				LASSO_MESSAGE_FORMAT_SOAP);
	}

	switch (lasso_profile_get_signature_verify_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			rc = profile->signature_status;
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			break;
		default:
			g_assert(0);
			break;
	}

cleanup:
	return rc;
}

int
lasso_saml20_profile_build_artifact_response(LassoProfile *profile)
{
	LassoSamlp2StatusResponse *response = NULL;
	int rc = 0;

	if ( ! LASSO_IS_SAMLP2_REQUEST_ABSTRACT(profile->request)) {
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}
	/* Setup the response */
	response = LASSO_SAMLP2_STATUS_RESPONSE(lasso_samlp2_artifact_response_new());
	lasso_assign_new_gobject(profile->response, response);
	response->ID = lasso_build_unique_id(32);
	lasso_assign_string(response->Version, "2.0");
	response->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	response->IssueInstant = lasso_get_current_time();
	lasso_assign_string(response->InResponseTo, LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	/* Add content */
	if (profile->private_data->artifact_message) {
		xmlDoc *doc;
		xmlNode *node;
		char *content = profile->private_data->artifact_message;
		doc = lasso_xml_parse_memory(content, strlen(content));
		if (doc) {
			node = xmlDocGetRootElement(doc);
			lasso_assign_new_gobject(LASSO_SAMLP2_ARTIFACT_RESPONSE(response)->any,
					lasso_misc_text_node_new_with_xml_node(node));
			lasso_release_doc(doc);
			lasso_saml20_profile_set_response_status(profile,
					LASSO_SAML2_STATUS_CODE_SUCCESS, NULL);
		} else {
			lasso_saml20_profile_set_response_status(profile,
					LASSO_SAML2_STATUS_CODE_RESPONDER,
					LASSO_PRIVATE_STATUS_CODE_FAILED_TO_RESTORE_ARTIFACT);
		}
	} else {
		/* if no artifact is present, it is a success anyway */
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_SUCCESS, NULL);
	}
	/* Setup the signature */
	lasso_check_good_rc(lasso_profile_saml20_setup_message_signature(profile,
				(LassoNode*)response));
	/* Serialize the message */
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(profile->response));
cleanup:
	return rc;
}

int
lasso_saml20_profile_process_artifact_response(LassoProfile *profile, const char *msg)
{
	LassoSamlp2ArtifactResponse *artifact_response;
	int rc = 0;

	artifact_response = (LassoSamlp2ArtifactResponse*)lasso_samlp2_artifact_response_new();
	lasso_check_good_rc(lasso_saml20_profile_process_any_response(profile,
				&artifact_response->parent, NULL, msg));
	/* XXX: check signature status */
	goto_cleanup_if_fail_with_rc(profile->response != NULL,
			critical_error(LASSO_PROFILE_ERROR_INVALID_RESPONSE));
	if (artifact_response->any == NULL) {
		rc = LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	} else {
		if (LASSO_IS_SAMLP2_REQUEST_ABSTRACT(artifact_response->any)) {
			lasso_assign_gobject(profile->request, artifact_response->any);
		} else if (LASSO_IS_SAMLP2_STATUS_RESPONSE(artifact_response->any)) {
			lasso_assign_gobject(profile->response, artifact_response->any);
		} else {
			rc = LASSO_PROFILE_ERROR_INVALID_RESPONSE;
		}
	}

cleanup:
	lasso_release_gobject(artifact_response);
	return rc;
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
		LASSO_SAML2_FIELD_REQUEST "=", LASSO_SAML2_FIELD_RESPONSE "=",
		LASSO_SAML2_FIELD_ARTIFACT "=", NULL };
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
		LassoSaml2Assertion *assertion, LassoProfile *profile)
{
	if (LASSO_IS_SAML2_ASSERTION(assertion) == FALSE) {
		return;
	}

	if (assertion->Subject != NULL && ! assertion->Subject->NameID && assertion->Subject->EncryptedID != NULL) {
		if (assertion->Subject->EncryptedID->original_data) { /* already decrypted */
			lasso_assign_gobject(assertion->Subject->NameID,
				assertion->Subject->EncryptedID->original_data);
		lasso_release_gobject(assertion->Subject->EncryptedID);
		} else { /* decrypt */
			int rc;
			GList *encryption_private_keys =
				lasso_server_get_encryption_private_keys(profile->server);

			rc = LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY;
			lasso_foreach_full_begin(xmlSecKey*, encryption_private_key, it,
					encryption_private_keys);
			{
				rc = lasso_saml2_encrypted_element_decrypt(
						assertion->Subject->EncryptedID,
						encryption_private_key,
						(LassoNode**)&assertion->Subject->NameID);
				if (rc == 0)
					break;
			}
			lasso_foreach_full_end();

			if (rc == 0) {
				lasso_release_gobject(assertion->Subject->EncryptedID);
			} else {
				message(G_LOG_LEVEL_WARNING, "Could not decrypt EncrypteID from"
						" assertion in session dump: %s", lasso_strerror(rc));
			}
		}
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
				profile);
		lasso_release_list(assertions);
	}

	return 0;
}

/**
 * lasso_saml20_profile_process_name_identifier_decryption:
 * @profile: the #LassoProfile object
 * @name_id: the field containing the #LassoSaml2NameID object
 * @encrypted_id: the field containing an encrypted #LassoSaml2NameID as a
 * #LassoSaml2EncryptedElement
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
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_null_param(name_id);
	lasso_null_param(encrypted_id);

	if (*name_id == NULL && *encrypted_id != NULL) {
		if (! LASSO_IS_SAML2_ENCRYPTED_ELEMENT(*encrypted_id)) {
			return LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER;
		}
		rc = LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY;
		lasso_foreach_full_begin(xmlSecKey*, encryption_private_key, it,
				lasso_server_get_encryption_private_keys(profile->server));
		{
			rc = lasso_saml2_encrypted_element_decrypt(*encrypted_id, encryption_private_key,
					&profile->nameIdentifier);
			if (rc == 0)
				break;
		}
		lasso_foreach_full_end();

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

/*
 * Request handling functions
 */

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
 * Return value: 0 if parsing is successful (even if signature validation fails), and otherwise,
 * LASSO_PROFILE_ERROR_INVALID_MSG, LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE, *
 * LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND.
 */
int
lasso_saml20_profile_process_any_request(LassoProfile *profile,
		LassoNode *request_node,
		const char *request_msg)
{
	int rc = 0;
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
	goto_cleanup_if_fail_with_rc(LASSO_IS_SAML2_NAME_ID(request_abstract->Issuer),
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
		const char *request_msg)
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

	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);

	switch (lasso_profile_get_signature_verify_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			rc = profile->signature_status;
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST:
			g_assert_not_reached();
			break;
	}

cleanup:
	return rc;
}

int
lasso_saml20_profile_init_request(LassoProfile *profile,
		const char *remote_provider_id,
		gboolean first_in_session,
		LassoSamlp2RequestAbstract *request_abstract,
		LassoHttpMethod http_method,
		LassoMdProtocolType protocol_type)
{
	LassoServer *server = NULL;
	LassoSession *session = NULL;
	LassoProvider *remote_provider = NULL;
	LassoSaml2NameID *name_id = NULL;
	char *remote_provider_id_auto = NULL;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(SAMLP2_REQUEST_ABSTRACT, request_abstract);

	if (http_method != LASSO_HTTP_METHOD_ANY &&
			http_method != LASSO_HTTP_METHOD_REDIRECT &&
			http_method != LASSO_HTTP_METHOD_POST &&
			http_method != LASSO_HTTP_METHOD_ARTIFACT_GET &&
			http_method != LASSO_HTTP_METHOD_ARTIFACT_POST &&
			http_method != LASSO_HTTP_METHOD_SOAP &&
			http_method != LASSO_HTTP_METHOD_PAOS) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	/* verify server and session object */
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	if (LASSO_IS_SESSION(profile->session)) {
		session = profile->session;
	}

	/*
	 * With PAOS the ECP client determines the remote provider.
	 * Everthing in the following block of code depends on
	 * establishing the remote provider and subsequetnly operating
	 * on the remote provider.
	 */
	if (http_method != LASSO_HTTP_METHOD_PAOS) {
		/* set remote provider Id */
		if (! remote_provider_id) {
			if (first_in_session) {
				if (! session) {
					return LASSO_PROFILE_ERROR_SESSION_NOT_FOUND;
				}
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
		if (LASSO_IS_SAML2_NAME_ID(name_id)) {
			lasso_assign_gobject(profile->nameIdentifier, (LassoNode*)name_id);
		}

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

	/* set signature */
	lasso_check_good_rc(lasso_profile_saml20_setup_message_signature(profile, profile->request));

cleanup:
	return rc;
}

static int
lasso_saml20_profile_build_redirect_request_msg(LassoProfile *profile, const char *url)
{
	return lasso_saml20_profile_build_http_redirect(profile,
			profile->request,
			url);
}

static int
lasso_saml20_profile_build_post_request_msg(LassoProfile *profile,
		const char *url)
{
	lasso_assign_string(profile->msg_url, url);
	lasso_assign_new_string(profile->msg_body,
			lasso_node_export_to_base64(profile->request));
	check_msg_body;
	return 0;
}

static int
lasso_saml20_profile_build_soap_request_msg(LassoProfile *profile, const char *url)
{
	lasso_assign_string(profile->msg_url, url);
	lasso_assign_new_string(profile->msg_body,
			lasso_node_export_to_soap(profile->request));
	check_msg_body;
	return 0;
}

/*
 * the url parameters is special for this function, it does not give the destination of the message
 * (it's implicit for the caller of this function) but where response should be posted later).
 */
static int
lasso_profile_saml20_build_paos_request_msg(LassoProfile *profile, const char *url)
{
	int rc = 0;
    LassoSamlp2AuthnRequest *request;
	LassoSamlp2IDPList *idp_list = NULL;
	char *message_id = NULL;

	lasso_extract_node_or_fail(request, profile->request, SAMLP2_AUTHN_REQUEST,
							   LASSO_PROFILE_ERROR_MISSING_REQUEST);

	if (lasso_profile_get_idp_list(profile)) {
		lasso_extract_node_or_fail(idp_list,
								   lasso_profile_get_idp_list(profile),
								   SAMLP2_IDP_LIST,
								   LASSO_PROFILE_ERROR_INVALID_IDP_LIST);
	}

	message_id = lasso_profile_get_message_id(profile);

	lasso_assign_new_string(profile->msg_body,
			lasso_node_export_to_paos_request_full(profile->request,
												   profile->server->parent.ProviderID, url,
												   message_id,
												   profile->msg_relayState,
												   request->IsPassive, request->ProviderName,
												   idp_list));

	check_msg_body;

cleanup:
	lasso_release_string(message_id);
	return rc;
}

int
lasso_saml20_profile_build_request_msg(LassoProfile *profile, const char *service,
		LassoHttpMethod method, const char *_url)
{
	char *made_url = NULL, *url;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);

	lasso_profile_clean_msg_info(profile);
	url = (char*)_url;

	/* check presence of a request */
	if (! LASSO_IS_SAMLP2_REQUEST_ABSTRACT(profile->request)) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
	}

	/* if not explicitely given, automatically determine an URI from the metadatas */
	if (url == NULL) {
		LassoProvider *provider;

		lasso_check_good_rc(get_provider(profile, &provider));
		made_url = url = get_url(provider, service, http_method_to_binding(method));
	}

	if (url) {
		lasso_assign_string(((LassoSamlp2RequestAbstract*)profile->request)->Destination,
				url);
	} else {
		rc = LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL;
		goto cleanup;
	}

	switch (method) {
		case LASSO_HTTP_METHOD_SOAP:
			rc = lasso_saml20_profile_build_soap_request_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_POST:
			rc = lasso_saml20_profile_build_post_request_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_REDIRECT:
			rc = lasso_saml20_profile_build_redirect_request_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_ARTIFACT_GET:
			rc = lasso_profile_saml20_build_artifact_get_request_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_ARTIFACT_POST:
			rc = lasso_profile_saml20_build_artifact_post_request_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_PAOS:
			rc = lasso_profile_saml20_build_paos_request_msg(profile, url);
			break;
		default:
			rc = LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
			break;
	}

cleanup:
	lasso_release_string(made_url);
	return rc;

}

/*
 * Response handling functions
 */

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
lasso_saml20_profile_init_response(LassoProfile *profile, LassoSamlp2StatusResponse *status_response,
		const char *status_code1, const char *status_code2)
{
	int rc = 0;

	lasso_bad_param(PROFILE, profile);
	if (! LASSO_IS_SAMLP2_STATUS_RESPONSE(status_response))
		return LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	lasso_assign_gobject(profile->response, status_response);

	lasso_assign_new_string(status_response->ID, lasso_build_unique_id(32));
	lasso_assign_string(status_response->Version, "2.0");
	if (LASSO_IS_SERVER(profile->server)) {
		lasso_assign_new_gobject(status_response->Issuer,
				LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
						profile->server->parent.ProviderID)));
	}
	lasso_assign_new_string(status_response->IssueInstant, lasso_get_current_time());
	if (LASSO_IS_SAMLP2_REQUEST_ABSTRACT(profile->request)) {
		lasso_assign_string(status_response->InResponseTo, 
				((LassoSamlp2RequestAbstract*)profile->request)->ID);
	}
	lasso_check_good_rc(lasso_profile_saml20_setup_message_signature(profile,
				profile->response));
	if (status_code1) {
		lasso_saml20_profile_set_response_status(profile,
				status_code1, status_code2);
	}

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
	LassoProvider *provider = NULL;

	lasso_bad_param(PROFILE, profile);
	lasso_bad_param(SAMLP2_STATUS_RESPONSE, status_response);
	/* verify request presence */
	lasso_extract_node_or_fail(request_abstract, profile->request, SAMLP2_REQUEST_ABSTRACT,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);
	/* look for identity object */
	if (needs_identity) {
		goto_cleanup_if_fail_with_rc(LASSO_IS_IDENTITY(profile->identity),
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
	lasso_saml20_profile_init_response(profile, status_response,
			LASSO_SAML2_STATUS_CODE_SUCCESS, NULL);

	switch (lasso_profile_get_signature_verify_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
			if (profile->signature_status) {
				lasso_saml20_profile_set_response_status(profile,
						LASSO_SAML2_STATUS_CODE_REQUESTER,
						LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
				return profile->signature_status;
			}
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST:
			g_assert_not_reached();
	}

cleanup:
	if (provider && provider_out)
		*provider_out = provider;
	return rc;

}

/**
 * lasso_saml20_profile_export_to_query:
 * @profile: a #LassoProfile
 * @msg: a #LassoNode to export as a query
 * @query: an ouput variable to store the result
 * @signature_method: the signature method for signing the query
 * @private_key_file:(allow-none): the private key to eventually sign the query
 * @private_key_password:(allow-none): the password of the private key if there is one
 *
 * Create a query following the DEFLATE encoding of the SAML 2.0 HTTP
 * Redirect binding. If the root message node has an XML signature, signature is removed and query
 * is signed.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
static int
lasso_saml20_profile_export_to_query(LassoProfile *profile, LassoNode *msg, char **query,
		LassoSignatureContext context) {
	char *unsigned_query = NULL;
	char *result = NULL;
	int rc = 0;

	unsigned_query = lasso_node_build_query(msg);
	goto_cleanup_if_fail_with_rc(unsigned_query != NULL,
			LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
	if (profile->msg_relayState) {
		unsigned_query = lasso_url_add_parameters(unsigned_query, 1, "RelayState",
				profile->msg_relayState, NULL);

		if (strlen(profile->msg_relayState) > 80) {
			message(G_LOG_LEVEL_WARNING, "Encoded a RelayState of more than 80 bytes, "
					"see #3.4.3 of saml-bindings-2.0-os");
		}
	}
	if (lasso_validate_signature_method(context.signature_method)) {
		result = lasso_query_sign(unsigned_query, context);
		goto_cleanup_if_fail_with_rc(result != NULL,
				LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		lasso_transfer_string(*query, result);
	} else {
		lasso_transfer_string(*query, unsigned_query);
	}
cleanup:
	lasso_release_string(unsigned_query);
	lasso_release_string(result);
	return rc;
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
	const char *url)
{
	char *query = NULL;
	int rc = 0;
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;

	goto_cleanup_if_fail_with_rc (url != NULL, LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	/* if message is signed, remove XML signature, add query signature */
	lasso_assign_signature_context(context, lasso_node_get_signature(msg));
	if (lasso_validate_signature_method(context.signature_method)) {
		lasso_node_remove_signature(msg);
	}
	lasso_check_good_rc(lasso_saml20_profile_export_to_query(profile, msg, &query, context));

	lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
	lasso_release(profile->msg_body);
	lasso_release(query);
	lasso_assign_new_signature_context(context, LASSO_SIGNATURE_CONTEXT_NONE);

cleanup:
	return rc;
}

static int
lasso_saml20_profile_build_redirect_response_msg(LassoProfile *profile, const char *url)
{
	return lasso_saml20_profile_build_http_redirect(profile,
			profile->response,
			url);
}

static int
lasso_saml20_profile_build_post_response_msg(LassoProfile *profile, const char *url)
{
	lasso_assign_string(profile->msg_url, url);
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_base64(profile->response));
	check_msg_body;
	return 0;
}

static int
lasso_saml20_profile_build_soap_response_msg(LassoProfile *profile)
{
	lasso_release_string(profile->msg_url);
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(profile->response));
	check_msg_body;
	return 0;
}


int
lasso_saml20_profile_build_response_msg(LassoProfile *profile, char *service,
		LassoHttpMethod method, const char *_url)
{
	LassoProvider *provider;
	char *made_url = NULL, *url;
	int rc = 0;

	lasso_bad_param(PROFILE, profile);

	lasso_profile_clean_msg_info(profile);
	lasso_check_good_rc(get_provider(profile, &provider));
	url = (char*)_url;

	/* check presence of a request */
	if (! LASSO_IS_SAMLP2_STATUS_RESPONSE(profile->response)) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_RESPONSE);
	}

	/* if not explicitely given, automatically determine an URI from the metadatas */
	if (url == NULL && service && method != LASSO_HTTP_METHOD_SOAP) {
		made_url = url = get_response_url(provider, service, http_method_to_binding(method));
	}

	/* only asynchronous bindings needs an URL for the response, SOAP does not need it, and PAOS
	 * is special (response is a SOAP request !?! ) */
	if (! url) {
		switch (method) {
			case LASSO_HTTP_METHOD_POST:
			case LASSO_HTTP_METHOD_REDIRECT:
			case LASSO_HTTP_METHOD_ARTIFACT_GET:
			case LASSO_HTTP_METHOD_ARTIFACT_POST:
			case LASSO_HTTP_METHOD_PAOS:
				goto_cleanup_with_rc(critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL));
			default:
				break;
		}
	}

	if (url) {
		lasso_assign_string(((LassoSamlp2StatusResponse*)profile->response)->Destination,
				url);
	}

	switch (method) {
		case LASSO_HTTP_METHOD_POST:
			rc = lasso_saml20_profile_build_post_response_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_REDIRECT:
			rc = lasso_saml20_profile_build_redirect_response_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_SOAP:
			rc = lasso_saml20_profile_build_soap_response_msg(profile);
			break;
		case LASSO_HTTP_METHOD_ARTIFACT_GET:
			rc = lasso_profile_saml20_build_artifact_get_response_msg(profile, url);
			break;
		case LASSO_HTTP_METHOD_ARTIFACT_POST:
			rc = lasso_profile_saml20_build_artifact_post_response_msg(profile, url);
			break;
		default:
			rc= LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
			break;
	}

cleanup:
	lasso_release_string(made_url);
	return rc;
}

static gboolean
_lasso_saml20_is_valid_issuer(LassoSaml2NameID *name_id) {
	if (! LASSO_IS_SAML2_NAME_ID(name_id))
		return FALSE;

	if (name_id->Format &&
			lasso_strisnotequal(name_id->Format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY))
	{
		return FALSE;
	}
	return TRUE;
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
		LassoHttpMethod *response_method,
		const char *response_msg)
{
	int rc = 0;
	LassoProvider *remote_provider = NULL;
	LassoServer *server = NULL;
	LassoSamlp2StatusResponse *response_abstract = NULL;
	LassoSamlp2Status *status = NULL;
	LassoSamlp2StatusCode *status_code1 = NULL;
	LassoMessageFormat format;
	gboolean missing_issuer = FALSE;

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
	if (response_method) {
		switch (format) {
			case LASSO_MESSAGE_FORMAT_SOAP:
				*response_method = LASSO_HTTP_METHOD_SOAP;
				break;
			case LASSO_MESSAGE_FORMAT_QUERY:
				*response_method = LASSO_HTTP_METHOD_REDIRECT;
				break;
			case LASSO_MESSAGE_FORMAT_BASE64:
				*response_method = LASSO_HTTP_METHOD_POST;
				break;
			default:
				return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		}
	}
	lasso_assign_gobject(profile->response, (LassoNode*)status_response);
	lasso_extract_node_or_fail(response_abstract, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	if (_lasso_saml20_is_valid_issuer(response_abstract->Issuer)) {
		lasso_assign_string(profile->remote_providerID, response_abstract->Issuer->content);
		remote_provider = lasso_server_get_provider(server, profile->remote_providerID);
	} else {
		missing_issuer = TRUE;
	}

	if (remote_provider) {
		/* verify the signature at the message level */
		if (content && doc && format != LASSO_MESSAGE_FORMAT_QUERY) {
			profile->signature_status =
				lasso_provider_verify_saml_signature(remote_provider, content, doc);
		} else if (format == LASSO_MESSAGE_FORMAT_QUERY) {
			profile->signature_status =
				lasso_provider_verify_query_signature(remote_provider, response_msg);
		} else {
			profile->signature_status = LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
		}
	} else {
		rc = LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
		profile->signature_status = LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
		goto cleanup;
	}

	/* verify status code */
	lasso_extract_node_or_fail(status, status_response->Status, SAMLP2_STATUS,
			LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	lasso_extract_node_or_fail(status_code1, status->StatusCode, SAMLP2_STATUS_CODE,
			LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	if (lasso_strisnotequal(status_code1->Value,LASSO_SAML2_STATUS_CODE_SUCCESS))
	{
		LassoSamlp2StatusCode *status_code2 = status_code1->StatusCode;
		rc = LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;

		if (!status_code2)
			goto cleanup;

		if (!status_code2->Value)
			goto cleanup;
		/* FIXME: what to do with secondary status code ? */
		if (lasso_strisequal(status_code2->Value, LASSO_SAML2_STATUS_CODE_REQUEST_DENIED)) {
			rc = LASSO_PROFILE_ERROR_REQUEST_DENIED;
		}
	}

cleanup:
	lasso_release_doc(doc);
	if (rc) {
		return rc;
	}
	switch (lasso_profile_get_signature_verify_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
			if (profile->signature_status) {
				return LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE;
			}
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST:
			g_assert_not_reached();
	}
	if (missing_issuer) {
		return LASSO_PROFILE_ERROR_MISSING_ISSUER;
	}
	return 0;
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
		const char *response_msg)
{
	return lasso_saml20_profile_process_soap_response_with_headers(
				profile, response_msg, NULL);
}

/**
 * lasso_saml20_profile_process_soap_response_with_headers:
 * @profile: the SAML 2.0 #LassoProfile object
 * @response_msg: xml response message
 * @header_return: If non-NULL the soap headers are returned at this
 *                 pointer as a #LassoSoapHeader object.
 *
 * Generic method for processing SAML 2.0 protocol message as a SOAP response.
 * The SOAP headers are returned via the header_return parameter
 * if the parameter is non-NULL. The caller is responsible for freeing
 * the SOAP header by calling lasso_release_gobject().
 *
 * Return value: 0 if successful; an error code otherwise.
 */
int
lasso_saml20_profile_process_soap_response_with_headers(LassoProfile *profile,
		const char *response_msg, LassoSoapHeader **header_return)
{
	int rc = 0;
	LassoSoapEnvelope *envelope = NULL;
	LassoSoapHeader *header = NULL;
	LassoSoapBody *body = NULL;
	LassoSaml2NameID *issuer = NULL;
	LassoProvider *remote_provider = NULL;
	LassoServer *server = NULL;
	LassoSamlp2StatusResponse *response_abstract = NULL;

	lasso_bad_param(PROFILE, profile);
	lasso_null_param(response_msg);
	if (header_return) {
		*header_return = NULL;
	}

	profile->signature_status = 0;

	/* Get the SOAP envelope */
	lasso_extract_node_or_fail(envelope, lasso_soap_envelope_new_from_message(response_msg),
							   SOAP_ENVELOPE, LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);

	/* Get and validate the SOAP body, assign it to the profile response */
	lasso_extract_node_or_fail(body, envelope->Body, SOAP_BODY,
							   LASSO_SOAP_ERROR_MISSING_BODY);
	if (body->any && LASSO_IS_NODE(body->any->data)) {
		lasso_assign_gobject(profile->response, body->any->data);
	} else {
		lasso_release_gobject(profile->response);
		goto_cleanup_with_rc(LASSO_SOAP_ERROR_MISSING_BODY);
	}

	/* Get the optional SOAP header, validate it, optionally return it */
	if (envelope->Header) {
		lasso_extract_node_or_fail(header, envelope->Header, SOAP_HEADER,
								   LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);
	}
	if (header_return) {
		if (header) {
			lasso_assign_gobject(*header_return, header);
		}
	}

	/* Extract and validate the response data */
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

	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, response_msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);
	switch (lasso_profile_get_signature_verify_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			rc = profile->signature_status;
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			break;
		default:
			g_assert(0);
			break;
	}

cleanup:
	lasso_release_gobject(envelope);
	return rc;
}

gint
lasso_saml20_profile_build_http_redirect_query_simple(LassoProfile *profile,
		LassoNode *msg,
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
	rc = lasso_saml20_profile_build_http_redirect(profile, msg, url);
cleanup:
	lasso_release(url);
	return rc;
}

gint
lasso_profile_saml20_setup_message_signature(LassoProfile *profile, LassoNode *request_or_response)
{
	lasso_bad_param(PROFILE, profile);
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;
	lasso_error_t rc = 0;

	switch (lasso_profile_get_signature_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_HINT_MAYBE:
			if (! lasso_flag_sign_messages) {
				message(G_LOG_LEVEL_WARNING, "message should be signed but no-sign-messages flag is " \
						"activated, so it won't be");
				return 0;
			}
			break;
		case LASSO_PROFILE_SIGNATURE_HINT_FORBID:
			return 0;
		default:
			break;
	}

	if (! LASSO_IS_SERVER(profile->server)) {
		return LASSO_PROFILE_ERROR_MISSING_SERVER;
	}
	lasso_check_good_rc(lasso_server_get_signature_context_for_provider_by_name(profile->server,
				profile->remote_providerID, &context));
	lasso_check_good_rc(lasso_node_set_signature(request_or_response, context));
cleanup:
	return rc;
}

/**
 * lasso_saml20_profile_setup_subject:
 * @profile: a #LassoProfile object
 * @subject: a #LassoSaml2Subject object
 *
 * Encrypt subject if necessary.
 */
int
lasso_saml20_profile_setup_subject(LassoProfile *profile,
		LassoSaml2Subject *subject)
{
	LassoProvider *remote_provider;

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	g_return_val_if_fail (LASSO_IS_PROVIDER(remote_provider), LASSO_ERROR_CAST_FAILED);
	if (! (lasso_provider_get_encryption_mode(remote_provider) & LASSO_ENCRYPTION_MODE_NAMEID)) {
		return 0;
	}
	return lasso_saml20_profile_setup_encrypted_node(remote_provider,
			(LassoNode**)subject->NameID,
			(LassoNode**)subject->EncryptedID);
}

gint
lasso_saml20_profile_setup_encrypted_node(LassoProvider *provider,
		LassoNode **node_to_encrypt, LassoNode **node_destination)
{
	LassoNode *encrypted_node;

	if (! LASSO_IS_PROVIDER(provider)) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}
	encrypted_node = (LassoNode*)lasso_node_encrypt(*node_to_encrypt,
			lasso_provider_get_encryption_public_key(provider),
			lasso_provider_get_encryption_sym_key_type(provider),
			provider->ProviderID);
	if (! encrypted_node) {
		return LASSO_DS_ERROR_ENCRYPTION_FAILED;
	}
	lasso_assign_new_gobject(*node_destination, encrypted_node);
	lasso_release_gobject(*node_to_encrypt);
	return 0;
}

/**
 * Check the profile->signature_status flag, if signature validation is activated, report it as an
 * error, if not not return 0.
 */
int
lasso_saml20_profile_check_signature_status(LassoProfile *profile) {
	int rc = 0;

	if (profile->signature_status) {
		switch (lasso_profile_get_signature_verify_hint(profile)) {
			case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
				rc = profile->signature_status;
				break;
			case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
				break;
			case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST:
				g_assert_not_reached();
				break;
		}
	}

	return rc;
}
