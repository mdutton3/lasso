/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/id-ff/lecp.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp)
{
	LassoProfile *profile;
	gchar *assertionConsumerServiceURL;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);

	assertionConsumerServiceURL = lasso_provider_get_metadata_one(
			LASSO_PROVIDER(profile->server), "AssertionConsumerServiceURL");
	if (assertionConsumerServiceURL == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	if (profile->request == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found");
		return LASSO_ERROR_UNDEFINED;
	}

	lecp->authnRequestEnvelope = lasso_lib_authn_request_envelope_new_full(
			LASSO_LIB_AUTHN_REQUEST(profile->request),
			LASSO_PROVIDER(profile->server)->ProviderID,
			assertionConsumerServiceURL);
	if (lecp->authnRequestEnvelope == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	profile->msg_body = lasso_node_dump(LASSO_NODE(lecp->authnRequestEnvelope), "utf-8", 0);
	if (profile->msg_body == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				"Error while exporting the AuthnRequestEnvelope to POST msg");
		return LASSO_ERROR_UNDEFINED;
	}

	return 0;
}

/**
 * lasso_lecp_build_authn_request_msg:
 * @lecp: a LassoLecp
 * 
 * Builds an authentication request. The data for the sending of the request are
 * stored in msg_url and msg_body (SOAP POST).
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
int
lasso_lecp_build_authn_request_msg(LassoLecp *lecp)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);

	profile->msg_url  = lasso_provider_get_metadata_one(
			remote_provider, "SingleSignOnServiceURL");
	profile->msg_body = lasso_node_export_to_soap(profile->request, NULL, NULL);
	if (profile->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}

int
lasso_lecp_build_authn_response_msg(LassoLecp *lecp)
{
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);
	profile->msg_url = g_strdup(lecp->assertionConsumerServiceURL);
	if (profile->msg_url == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}
	profile->msg_body = lasso_node_export_to_base64(profile->response, NULL, NULL);
	if (profile->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}

gint
lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp)
{
	LassoProfile  *profile;
	LassoProvider *provider;
	gchar         *assertionConsumerServiceURL;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);

	if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found");
		return LASSO_ERROR_UNDEFINED;
	}

	provider = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
	if (provider == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				profile->remote_providerID);
	}

	/* build lib:AuthnResponse */
	lasso_login_build_authn_response_msg(LASSO_LOGIN(lecp));

	assertionConsumerServiceURL = lasso_provider_get_metadata_one(
			provider, "AssertionConsumerServiceURL");
	if (assertionConsumerServiceURL == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	if (LASSO_PROFILE(lecp)->msg_body)
		g_free(LASSO_PROFILE(lecp)->msg_body);

	if (LASSO_PROFILE(lecp)->msg_url)
		g_free(LASSO_PROFILE(lecp)->msg_url);

	lecp->authnResponseEnvelope = lasso_lib_authn_response_envelope_new(
			LASSO_LIB_AUTHN_RESPONSE(profile->response),
			assertionConsumerServiceURL);
	LASSO_PROFILE(lecp)->msg_body = lasso_node_export_to_soap(
			LASSO_NODE(lecp->authnResponseEnvelope), NULL, NULL);

	if (LASSO_PROFILE(lecp)->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}

/*
 * lasso_lecp_init_authn_request:
 * @lecp: a LassoLecp
 * @remote_providerID: the providerID of the identity provider. When NULL, the first
 *                     identity provider is used.
 *
 */
int
lasso_lecp_init_authn_request(LassoLecp *lecp, const char *remote_providerID)
{
	gint res;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	/* FIXME : BAD usage of http_method
	   using POST method so that the lib:AuthnRequest is initialize with
	   a signature template */
	res = lasso_login_init_authn_request(LASSO_LOGIN(lecp), remote_providerID,
			LASSO_HTTP_METHOD_POST);

	return res;
}

int
lasso_lecp_process_authn_request_msg(LassoLecp *lecp, const char *authn_request_msg)
{
	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
	g_return_val_if_fail(authn_request_msg != NULL, -1);

	return lasso_login_process_authn_request_msg(LASSO_LOGIN(lecp), authn_request_msg);
}

int
lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp, const char *request_msg)
{
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
	g_return_val_if_fail(request_msg!=NULL, -1);

	lecp->authnRequestEnvelope = lasso_lib_authn_request_envelope_new();
	format = lasso_node_init_from_message(LASSO_NODE(lecp->authnRequestEnvelope), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	LASSO_PROFILE(lecp)->request = LASSO_NODE(g_object_ref(
			lecp->authnRequestEnvelope->AuthnRequest));
	if (LASSO_PROFILE(lecp)->request == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found");
		return LASSO_ERROR_UNDEFINED;
	}

	return 0;
}

int
lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp, const char *response_msg)
{
	LassoProfile *profile;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
	g_return_val_if_fail(response_msg!=NULL, -2);

	profile = LASSO_PROFILE(lecp);

	lecp->authnResponseEnvelope = lasso_lib_authn_response_envelope_new(NULL, NULL);
	format = lasso_node_init_from_message(LASSO_NODE(lecp->authnResponseEnvelope),
			response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	profile->response = g_object_ref(lecp->authnResponseEnvelope->AuthnResponse);
	if (profile->response == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found");
		return LASSO_ERROR_UNDEFINED;
	}

	lecp->assertionConsumerServiceURL = g_strdup(
			lecp->authnResponseEnvelope->AssertionConsumerServiceURL);
	if (lecp->assertionConsumerServiceURL == NULL){
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	return 0;
}

void
lasso_lecp_destroy(LassoLecp *lecp)
{
	g_object_unref(G_OBJECT(lecp));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
finalize(GObject *object)
{  
	debug("Lecp object 0x%p finalized ...", object);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLecp *lecp)
{
	lecp->authnRequestEnvelope = NULL;
	lecp->authnResponseEnvelope = NULL;
	lecp->assertionConsumerServiceURL = NULL;
}

static void
class_init(LassoLecpClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_lecp_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLecpClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLecp),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_LOGIN,
				"LassoLecp", &this_info, 0);
	}
	return this_type;
}

LassoLecp*
lasso_lecp_new(LassoServer *server)
{
	LassoLecp *lecp;

	lecp = g_object_new(LASSO_TYPE_LECP, NULL);
	LASSO_PROFILE(lecp)->server = server;

	return lecp;
}
