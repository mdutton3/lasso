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

#include <glib.h>
#include <glib/gprintf.h>

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/xml/errors.h>
#include <lasso/xml/samlp_response.h>
#include <lasso/xml/samlp_request.h>
#include <lasso/xml/lib_authn_response.h>
#include <lasso/xml/lib_status_response.h>
#include <lasso/environs/profile.h>

#include <lasso/lasso_config.h>

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
	const xmlChar *name;

	lassoRequestType type = LASSO_REQUEST_TYPE_INVALID;

	/* FIXME: totally lacking error checking */

	doc = xmlParseMemory(soap, strlen(soap));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "s", LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression("//s:Body/*", xpathCtx);

	name = xpathObj->nodesetval->nodeTab[0]->name;

	if (xmlStrEqual(name, "Request")) {
		type = LASSO_REQUEST_TYPE_LOGIN;
	}
	else if (xmlStrEqual(name, "LogoutRequest")) {
		type = LASSO_REQUEST_TYPE_LOGOUT;
	}
	else if (xmlStrEqual(name, "FederationTerminationNotification")) {
		type = LASSO_REQUEST_TYPE_DEFEDERATION;
	}
	else if (xmlStrEqual(name, "RegisterNameIdentifierRequest")) {
		type = LASSO_REQUEST_TYPE_NAME_REGISTRATION;
	}
	else if (xmlStrEqual(name, "NameIdentifierMappingRequest")) {
		type = LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING;
	}
	else if (xmlStrEqual(name, "AuthnRequest")) {
		type = LASSO_REQUEST_TYPE_LECP;
	}
	else {
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
		message(G_LOG_LEVEL_WARNING, "Failed to create the identity from the identity dump");
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

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode, *t;
	LassoProfile *profile = LASSO_PROFILE(node);

	xmlnode = xmlNewNode(NULL, "Profile");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, "Version", "2");

	/* XXX: server is not saved in profile dump */
	/* (what was the reason ?)
	if (profile->server) {
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(profile->server)));
	}
	*/

	if (profile->request) {
		t = xmlNewTextChild(xmlnode, NULL, "Request", NULL);
		xmlAddChild(t, lasso_node_get_xmlNode(profile->request));
	}
	if (profile->response) {
		t = xmlNewTextChild(xmlnode, NULL, "Response", NULL);
		xmlAddChild(t, lasso_node_get_xmlNode(profile->response));
	}
	if (profile->nameIdentifier)
		xmlNewTextChild(xmlnode, NULL, "NameIdentifier", profile->nameIdentifier);
	if (profile->remote_providerID)
		xmlNewTextChild(xmlnode, NULL, "RemoteProviderID", profile->remote_providerID);
	if (profile->msg_url)
		xmlNewTextChild(xmlnode, NULL, "MsgUrl", profile->msg_url);
	if (profile->msg_body)
		xmlNewTextChild(xmlnode, NULL, "MsgBody", profile->msg_body);
	if (profile->msg_relayState)
		xmlNewTextChild(xmlnode, NULL, "MsgRelayState", profile->msg_relayState);
	/* XXX: save signature status ? */
	
	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoProfile *profile = LASSO_PROFILE(node);
	xmlNode *t;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "NameIdentifier") == 0)
			profile->nameIdentifier = xmlNodeGetContent(t);
		if (strcmp(t->name, "RemoteProviderID") == 0)
			profile->remote_providerID = xmlNodeGetContent(t);
		if (strcmp(t->name, "MsgUrl") == 0)
			profile->msg_url = xmlNodeGetContent(t);
		if (strcmp(t->name, "MsgBody") == 0)
			profile->msg_body = xmlNodeGetContent(t);
		if (strcmp(t->name, "MsgRelayState") == 0)
			profile->msg_relayState = xmlNodeGetContent(t);

		if (strcmp(t->name, "Server") == 0) {
			LassoServer *s;
			s = g_object_new(LASSO_TYPE_SERVER, NULL);
			LASSO_NODE_GET_CLASS(s)->init_from_xml(LASSO_NODE(s), t);
		}

		if (strcmp(t->name, "Request") == 0) {
			xmlNode *t2 = t->children;
			while (t2 && t2->type != XML_ELEMENT_NODE)
				t2 = t2->next;
			if (t2)
				profile->request = lasso_node_new_from_xmlNode(t2);
		}
		if (strcmp(t->name, "Response") == 0) {
			xmlNode *t2 = t->children;
			while (t2 && t2->type != XML_ELEMENT_NODE)
				t2 = t2->next;
			if (t2)
				profile->response = lasso_node_new_from_xmlNode(t2);
		}
		t = t->next;
	}
}


/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoProfile *profile = LASSO_PROFILE(object);

	if (profile->private->dispose_has_run) {
		return;
	}
	profile->private->dispose_has_run = TRUE;

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

	g_free(profile->nameIdentifier);
	g_free(profile->remote_providerID);
	g_free(profile->msg_url);
	g_free(profile->msg_body);
	g_free(profile->msg_relayState);

	g_free (profile->private);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoProfile *profile)
{
	profile->private = g_new (LassoProfilePrivate, 1);
	profile->private->dispose_has_run = FALSE;

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
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

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

