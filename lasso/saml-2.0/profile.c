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

#include <xmlsec/base64.h>

#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/saml-2.0/profileprivate.h>
#include <lasso/saml-2.0/profile.h>

#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/profile.h>
#include <lasso/id-ff/profileprivate.h>
#include <lasso/id-ff/serverprivate.h>

#include <lasso/xml/saml-2.0/samlp2_request_abstract.h>
#include <lasso/xml/saml-2.0/samlp2_artifact_resolve.h>
#include <lasso/xml/saml-2.0/samlp2_artifact_response.h>
#include <lasso/xml/saml-2.0/samlp2_name_id_mapping_response.h>
#include <lasso/xml/saml-2.0/samlp2_status_response.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>

static char* lasso_saml20_profile_build_artifact(LassoProvider *provider);

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
	profile->private_data->artifact = lasso_saml20_profile_build_artifact(
			LASSO_PROVIDER(profile->server));
	if (part == 0) {
		profile->private_data->artifact_message = lasso_node_dump(profile->request);
	} else if (part == 1) {
		profile->private_data->artifact_message = lasso_node_dump(profile->response);
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

void
lasso_saml20_profile_set_response_status(LassoProfile *profile, const char *status_code_value)
{
	LassoSamlp2Status *status;

	status = LASSO_SAMLP2_STATUS(lasso_samlp2_status_new());
	status->StatusCode = LASSO_SAMLP2_STATUS_CODE(lasso_samlp2_status_code_new());
	status->StatusCode->Value = g_strdup(status_code_value);

	if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0 &&
			strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_VERSION_MISMATCH) != 0 &&
			strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_REQUESTER) != 0) {
		status->StatusCode->Value = g_strdup(LASSO_SAML2_STATUS_CODE_RESPONDER);
		status->StatusCode->StatusCode = LASSO_SAMLP2_STATUS_CODE(
				lasso_samlp2_status_code_new());
		status->StatusCode->StatusCode->Value = g_strdup(status_code_value);
	}

	if (LASSO_IS_SAMLP2_RESPONSE(profile->response) ||
			LASSO_IS_SAMLP2_ARTIFACT_RESPONSE(profile->response) ||
			LASSO_IS_SAMLP2_NAME_ID_MAPPING_RESPONSE(profile->response) ||
			LASSO_IS_SAMLP2_STATUS_RESPONSE(profile->response)) {
		LassoSamlp2StatusResponse *response;
		response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);
		if (response->Status)
			lasso_node_destroy(LASSO_NODE(response->Status));
		response->Status = status;
		return;
	}

	message(G_LOG_LEVEL_CRITICAL, "Failed to set status");
	g_assert_not_reached();
}


int
lasso_saml20_profile_init_artifact_resolve(LassoProfile *profile,
		const char *msg, LassoHttpMethod method)
{
	char **query_fields;
	char *artifact_b64 = NULL, *provider_succinct_id_b64;
	char provider_succinct_id[21];
	char artifact[45];
	LassoSamlp2RequestAbstract *request;
	int i;

	if (method == LASSO_HTTP_METHOD_ARTIFACT_GET) {
		query_fields = urlencoded_to_strings(msg);
		for (i=0; query_fields[i]; i++) {
			if (strncmp(query_fields[i], "SAMLart=", 8) != 0) {
				xmlFree(query_fields[i]);
				continue;
			}
			artifact_b64 = g_strdup(query_fields[i]+8);
			xmlFree(query_fields[i]);
		}
		g_free(query_fields);
		if (artifact_b64 == NULL) {
			return LASSO_PROFILE_ERROR_MISSING_ARTIFACT;
		}
	} else {
		artifact_b64 = g_strdup(msg);
	}

	i = xmlSecBase64Decode((xmlChar*)artifact_b64, (xmlChar*)artifact, 45);
	if (i < 0 || i > 44) {
		g_free(artifact_b64);
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}

	if (artifact[0] != 0 || artifact[1] != 4) { /* wrong type code */
		g_free(artifact_b64);
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}

	/* XXX: index endpoint */

	memcpy(provider_succinct_id, artifact+4, 20);
	provider_succinct_id[20] = 0;

	provider_succinct_id_b64 = (char*)xmlSecBase64Encode((xmlChar*)provider_succinct_id, 20, 0);

	profile->remote_providerID = lasso_server_get_providerID_from_hash(
			profile->server, provider_succinct_id_b64);
	xmlFree(provider_succinct_id_b64);
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	if (profile->request) {
		lasso_node_destroy(profile->request);
	}
	profile->request = lasso_samlp2_artifact_resolve_new();
	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	LASSO_SAMLP2_ARTIFACT_RESOLVE(request)->Artifact = artifact_b64;
	request->ID = lasso_build_unique_id(32);
	request->Version = g_strdup("2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	request->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (profile->server->certificate) {
		request->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		request->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}

	return 0;
}

int
lasso_saml20_profile_process_artifact_resolve(LassoProfile *profile, const char *msg)
{
	LassoProvider *remote_provider;
	int rc;

	if (profile->request) {
		lasso_node_destroy(profile->request);
	}

	profile->request = lasso_node_new_from_soap(msg);
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	if (! LASSO_IS_SAMLP2_ARTIFACT_RESOLVE(profile->request)) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	profile->remote_providerID = g_strdup(LASSO_SAMLP2_REQUEST_ABSTRACT(
			profile->request)->Issuer->content);
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);

	rc = lasso_provider_verify_signature(remote_provider, msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);

	profile->private_data->artifact = g_strdup(
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
		LASSO_SAMLP2_ARTIFACT_RESPONSE(response)->any = resp;
	}
	response->ID = lasso_build_unique_id(32);
	response->Version = g_strdup("2.0");
	response->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	response->IssueInstant = lasso_get_current_time();
	response->InResponseTo = g_strdup(LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	response->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (profile->server->certificate) {
		response->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		response->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	response->private_key_file = g_strdup(profile->server->private_key);
	response->certificate_file = g_strdup(profile->server->certificate);

	profile->response = LASSO_NODE(response);
	
	if (resp == NULL) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUESTER);
	} else {
		lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_SUCCESS);
	}
	profile->msg_body = lasso_node_export_to_soap(profile->response);
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
		profile->response = lasso_samlp2_response_new();
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}
	artifact_response = LASSO_SAMLP2_ARTIFACT_RESPONSE(response);

	if (artifact_response->any == NULL) {
		profile->response = lasso_samlp2_response_new();
		return LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}
	
	profile->response = g_object_ref(artifact_response->any);
	lasso_node_destroy(response);

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
		gpointer key, LassoSaml2Assertion *assertion, gpointer data)
{
	if (LASSO_IS_SAML2_ASSERTION(assertion) == FALSE) {
		return;
	}

	if (assertion->Subject != NULL && assertion->Subject->EncryptedID != NULL) {
		assertion->Subject->NameID = LASSO_SAML2_NAME_ID(
				assertion->Subject->EncryptedID->original_data);
		assertion->Subject->EncryptedID = NULL;
	}
}

gint
lasso_saml20_profile_set_session_from_dump(LassoProfile *profile)
{
	if (profile->session != NULL && profile->session->assertions != NULL) {
		g_hash_table_foreach(profile->session->assertions,
				(GHFunc)lasso_saml20_profile_set_session_from_dump_decrypt,
				NULL);
	}

	return 0;
}
