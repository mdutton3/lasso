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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/xml/samlp_response.h>
#include <lasso/xml/samlp_request.h>
#include <lasso/xml/lib_authn_response.h>
#include <lasso/xml/lib_status_response.h>

#include <lasso/id-ff/profile.h>

struct _LassoProfilePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public functions                                                          */
/*****************************************************************************/

LassoSamlNameIdentifier*
lasso_profile_get_nameIdentifier(LassoProfile *ctx)
{
	LassoProvider *remote_provider;
	LassoFederation *federation;

	g_return_val_if_fail(LASSO_IS_PROFILE(ctx), NULL);

	g_return_val_if_fail(LASSO_IS_SERVER(ctx->server), NULL);
	g_return_val_if_fail(LASSO_IS_IDENTITY(ctx->identity), NULL);
	g_return_val_if_fail(ctx->remote_providerID != NULL, NULL);

	remote_provider = g_hash_table_lookup(ctx->server->providers, ctx->remote_providerID);
	if (remote_provider == NULL)
		return NULL;

	federation = g_hash_table_lookup(ctx->identity->federations, ctx->remote_providerID);
	if (federation == NULL)
		return NULL;

	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		if (federation->remote_nameIdentifier)
			return federation->remote_nameIdentifier;
		return federation->local_nameIdentifier;
	}

	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		if (federation->local_nameIdentifier)
			return federation->local_nameIdentifier;
		return federation->remote_nameIdentifier;
	}

	return NULL;
}

lassoRequestType
lasso_profile_get_request_type_from_soap_msg(const gchar *soap)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	lassoRequestType type = LASSO_REQUEST_TYPE_INVALID;
	const char *name = NULL;

	doc = xmlParseMemory(soap, strlen(soap));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "s", LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression("//s:Body/*", xpathCtx);

	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr)
		name = xpathObj->nodesetval->nodeTab[0]->name;

	if (name == NULL) {
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
	} else {
		message(G_LOG_LEVEL_WARNING, "Unkown node name : %s", name);
	}

	xmlFreeDoc(doc);
	xmlXPathFreeContext(xpathCtx);
	xmlXPathFreeObject(xpathObj);

	return type;
}

/**
 * lasso_profile_is_liberty_query
 * @query: HTTP query string
 *
 * Tests the query string to know if the URL is called as the result of a
 * Liberty redirect (action initiated elsewhere) or not.
 *
 * Returns: TRUE if lasso query, FALSE otherwise
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


LassoIdentity*
lasso_profile_get_identity(LassoProfile *ctx)
{
	if (ctx->identity && g_hash_table_size(ctx->identity->federations))
		return ctx->identity;
	return NULL;
}

LassoSession*
lasso_profile_get_session(LassoProfile *ctx)
{
	if (ctx->session && g_hash_table_size(ctx->session->assertions))
		return ctx->session;
	return NULL;
}

gboolean
lasso_profile_is_identity_dirty(LassoProfile *ctx)
{
	return (ctx->identity && ctx->identity->is_dirty);
}

gboolean
lasso_profile_is_session_dirty(LassoProfile *ctx)
{
	return (ctx->session && ctx->session->is_dirty);
}

void
lasso_profile_set_response_status(LassoProfile *ctx, const char *statusCodeValue)
{
	LassoSamlpStatus *status;

	status = lasso_samlp_status_new();
	status->StatusCode = lasso_samlp_status_code_new();
	status->StatusCode->Value = g_strdup(statusCodeValue);

	if (LASSO_IS_SAMLP_RESPONSE(ctx->response)) {
		LassoSamlpResponse *response = LASSO_SAMLP_RESPONSE(ctx->response);
		if (response->Status) g_object_unref(response->Status);
		response->Status = status;
		return;
	}
	if (LASSO_IS_LIB_STATUS_RESPONSE(ctx->response)) {
		LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(ctx->response);
		if (response->Status) g_object_unref(response->Status);
		response->Status = status;
		return;
	}

	message(G_LOG_LEVEL_CRITICAL, "Failed to set status");
	g_assert_not_reached();
} 

gint
lasso_profile_set_identity_from_dump(LassoProfile *ctx, const gchar *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	ctx->identity = lasso_identity_new_from_dump(dump);
	if (ctx->identity == NULL) {
		message(G_LOG_LEVEL_WARNING,
				"Failed to create the identity from the identity dump");
		return -1;
	}
	ctx->identity->is_dirty = FALSE;

	return 0;
}

gint
lasso_profile_set_session_from_dump(LassoProfile *ctx, const gchar  *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	ctx->session = lasso_session_new_from_dump(dump);
	if (ctx->session == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to create the session from the session dump");
		return -1;
	}
	ctx->session->is_dirty = FALSE;

	return 0;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, request) },
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, response) },
	{ "NameIdentifier", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, nameIdentifier) },
	{ "RemoteProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, remote_providerID) },
	{ "MsgUrl", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_url) },
	{ "MsgBody", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_body) },
	{ "MsgRelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_relayState) },
	{ NULL, 0, 0}
};


static LassoNodeClass *parent_class = NULL;

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

	debug("Profile object 0x%x disposed ...", profile);

	/* XXX unref reference counted objects */
	/* lasso_server_destroy(profile->server);
	lasso_identity_destroy(profile->identity);
	lasso_session_destroy(profile->session);

	lasso_node_destroy(profile->request);
	lasso_node_destroy(profile->response);
	*/

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(profile));
}

static void
finalize(GObject *object)
{
	LassoProfile *profile = LASSO_PROFILE(object);

	debug("Profile object 0x%x finalized ...", object);

	g_free(profile->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoProfile *profile)
{
	profile->private_data = g_new(LassoProfilePrivate, 1);
	profile->private_data->dispose_has_run = FALSE;

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

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
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
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoProfile", &this_info, 0);
	}
	return this_type;
}

LassoProfile*
lasso_profile_new(LassoServer *server, LassoIdentity *identity, LassoSession *session)
{
	LassoProfile *profile = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	profile = g_object_new(LASSO_TYPE_PROFILE, NULL);
	profile->identity = identity;
	profile->session = session;

	return profile;
}

gchar*
lasso_profile_dump(LassoProfile *profile)
{
	return lasso_node_dump(LASSO_NODE(profile), NULL, 1);
}

