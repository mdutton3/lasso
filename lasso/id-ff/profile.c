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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/xml/samlp_response.h>
#include <lasso/xml/samlp_request.h>
#include <lasso/xml/lib_authn_response.h>
#include <lasso/xml/lib_status_response.h>

#include <lasso/id-ff/profile.h>
#include <lasso/id-ff/profileprivate.h>

struct _LassoProfilePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public functions                                                          */
/*****************************************************************************/


/**
 * lasso_profile_get_nameIdentifier:
 * @profile: a #LassoProifle
 *
 * Looks up appropriate federation in object and gets the service provider name
 * identifier.
 *
 * Return value: the name identifier or NULL if none was found.  The
 *     #LassoSamlNameIdentifier object is internally allocated and must not be
 *     freed by the caller.
 **/
LassoSamlNameIdentifier*
lasso_profile_get_nameIdentifier(LassoProfile *profile)
{
	LassoProvider *remote_provider;
	LassoFederation *federation;

	g_return_val_if_fail(LASSO_IS_PROFILE(profile), NULL);

	g_return_val_if_fail(LASSO_IS_SERVER(profile->server), NULL);
	g_return_val_if_fail(LASSO_IS_IDENTITY(profile->identity), NULL);
	g_return_val_if_fail(profile->remote_providerID != NULL, NULL);

	remote_provider = g_hash_table_lookup(
			profile->server->providers, profile->remote_providerID);
	if (remote_provider == NULL)
		return NULL;

	federation = g_hash_table_lookup(
			profile->identity->federations, profile->remote_providerID);
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

	doc = xmlParseMemory(soap, strlen(soap));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "s", LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression("//s:Body/*", xpathCtx);

	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		name = xpathObj->nodesetval->nodeTab[0]->name;
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
	} else if (strcmp(name, "Query") == 0) {
		if (strcmp(ns->href, LASSO_DISCO_HREF) == 0) {
			type = LASSO_REQUEST_TYPE_DISCO_QUERY;
		} else {
			type = LASSO_REQUEST_TYPE_DST_QUERY;
		}
	} else if (strcmp(name, "Modify") == 0) {
		if (strcmp(ns->href, LASSO_DISCO_HREF) == 0) {
			type =LASSO_REQUEST_TYPE_DISCO_MODIFY;
		} else {
			type =LASSO_REQUEST_TYPE_DST_MODIFY;	
		}
	} else {
		message(G_LOG_LEVEL_WARNING, "Unkown node name : %s", name);
	}

	xmlFreeDoc(doc);
	xmlXPathFreeContext(xpathCtx);
	xmlXPathFreeObject(xpathObj);

	return type;
}

/**
 * lasso_profile_is_liberty_query:
 * @query: HTTP query string
 *
 * Tests the query string to know if the URL is called as the result of a
 * Liberty redirect (action initiated elsewhere) or not.
 *
 * Return value: TRUE if lasso query, FALSE otherwise
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
 * Return value: the identity or NULL if it none was found.  The #LassoIdentity
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
 * Return value: the session or NULL if it none was found.  The #LassoSession
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
	return (profile->session && profile->session->is_dirty);
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
		if (response->Status) lasso_node_destroy(LASSO_NODE(response->Status));
		response->Status = status;
		return;
	}
	if (LASSO_IS_LIB_STATUS_RESPONSE(profile->response)) {
		LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(profile->response);
		if (response->Status) lasso_node_destroy(LASSO_NODE(response->Status));
		response->Status = status;
		return;
	}

	message(G_LOG_LEVEL_CRITICAL, "Failed to set status");
	g_assert_not_reached();
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

	profile->identity = lasso_identity_new_from_dump(dump);
	if (profile->identity == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP);

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
lasso_profile_set_session_from_dump(LassoProfile *profile, const gchar  *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->session = lasso_session_new_from_dump(dump);
	if (profile->session == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_SESSION_DUMP);
	profile->session->is_dirty = FALSE;

	return 0;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, request) },
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, response) },
	{ "NameIdentifier", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoProfile, nameIdentifier) },
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

	lasso_server_destroy(profile->server);
	profile->server = NULL;
	lasso_identity_destroy(profile->identity);
	profile->identity = NULL;
	lasso_session_destroy(profile->session);
	profile->session = NULL;

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(profile));
}

static void
finalize(GObject *object)
{
	LassoProfile *profile = LASSO_PROFILE(object);
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

