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
#include "./sessionprivate.h"

#include "../saml-2.0/profileprivate.h"
#include "../utils.h"
#include "../debug.h"

/*****************************************************************************/
/* public functions                                                          */
/*****************************************************************************/

/**
 * lasso_profile_get_nameIdentifier:
 * @profile: a #LassoProfile
 *
 * Looks up appropriate federation in object and gets the service provider name
 * identifier (which is actually a #LassoSamlNameIdentifier in ID-FF 1.2 and
 * #LassoSaml2NameID in SAML 2.0).
 *
 * Return value: the name identifier or NULL if none was found.  The #LassoNode
 *     object is internally allocated and must not be freed by the caller.
 **/
LassoNode*
lasso_profile_get_nameIdentifier(LassoProfile *profile)
{
	LassoProvider *remote_provider;
	LassoFederation *federation;
	char *name_id_sp_name_qualifier;

	g_return_val_if_fail(LASSO_IS_PROFILE(profile), NULL);

	g_return_val_if_fail(LASSO_IS_SERVER(profile->server), NULL);
	g_return_val_if_fail(LASSO_IS_IDENTITY(profile->identity), NULL);
	g_return_val_if_fail(profile->remote_providerID != NULL, NULL);

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (remote_provider == NULL)
		return NULL;

	if (remote_provider->private_data->affiliation_id) {
		name_id_sp_name_qualifier = remote_provider->private_data->affiliation_id;
	} else {
		name_id_sp_name_qualifier = profile->remote_providerID;
	}

	if (name_id_sp_name_qualifier == NULL)
		return NULL;

	federation = g_hash_table_lookup(
			profile->identity->federations,
			name_id_sp_name_qualifier);
	if (federation == NULL)
		return NULL;

	if (federation->remote_nameIdentifier)
		return federation->remote_nameIdentifier;

	return federation->local_nameIdentifier;
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

	if (soap == NULL)
		return LASSO_REQUEST_TYPE_INVALID;

	doc = xmlParseMemory(soap, strlen(soap));
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
	} else if (strcmp(name, "Query") == 0) {
		if (strcmp((char*)ns->href, LASSO_DISCO_HREF) == 0) {
			type = LASSO_REQUEST_TYPE_DISCO_QUERY;
		} else if (strcmp((char*)ns->href, LASSO_IDWSF2_DISCO_HREF) == 0) {
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
	} else if (strcmp(name, "ManageNameIDRequest") == 0) {
		type = LASSO_REQUEST_TYPE_NAME_ID_MANAGEMENT;
	} else if (strcmp(name, "SvcMDRegister") == 0) {
		type = LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_REGISTER;
	} else if (strcmp(name, "SvcMDAssociationAdd") == 0) {
		type = LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_ASSOCIATION_ADD;
	} else {
		message(G_LOG_LEVEL_WARNING, "Unknown node name : %s", name);
	}

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	lasso_release_doc(doc);

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
	return lasso_session_is_dirty(profile->session);
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

char*
lasso_profile_get_artifact(LassoProfile *profile)
{
	return g_strdup(profile->private_data->artifact);
}

char*
lasso_profile_get_artifact_message(LassoProfile *profile)
{
	return g_strdup(profile->private_data->artifact_message);
}

void
lasso_profile_set_artifact_message(LassoProfile *profile, char *message)
{
	lasso_assign_string(profile->private_data->artifact_message, message);
}

/**
 * lasso_profile_get_server:
 * @profile: a #LassoProfile object
 *
 * Return the #LassoServer linked to this profile object. A profile object should always contains
 * one. It allows to find metadatas of other providers and to know our own metadatas.
 *
 * Return value: a #LassoServer or NULL if profile is not a #LassoProfile or no #LassoServer object
 * was setup at the creation of this profile.
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


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, request), NULL, NULL, NULL},
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoProfile, response), NULL, NULL, NULL},
	{ "NameIdentifier", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoProfile, nameIdentifier), NULL, NULL, NULL},
	{ "RemoteProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, remote_providerID), NULL, NULL, NULL},
	{ "MsgUrl", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_url), NULL, NULL, NULL},
	{ "MsgBody", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_body), NULL, NULL, NULL},
	{ "MsgRelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProfile, msg_relayState), NULL, NULL, NULL},
	{ "HttpRequestMethod", SNIPPET_CONTENT | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoProfile, http_request_method), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoProfile *profile = LASSO_PROFILE(node);

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);

	if (profile->private_data->artifact) {
		xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Artifact",
			(xmlChar*)profile->private_data->artifact);
	}

	if (profile->private_data->artifact_message) {
		xmlNewTextChild(xmlnode, NULL, (xmlChar*)"ArtifactMessage",
			(xmlChar*)profile->private_data->artifact_message);
	}

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoProfile *profile = LASSO_PROFILE(node);
	xmlNode *t;

	parent_class->init_from_xml(node, xmlnode);

	if (xmlnode == NULL)
		return LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;

	t = xmlnode->children;
	while (t) {
		xmlChar *s;

		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		if (strcmp((char*)t->name, "Artifact") == 0) {
			s = xmlNodeGetContent(t);
			lasso_assign_string(profile->private_data->artifact, (char*)s);
			xmlFree(s);
		} else if (strcmp((char*)t->name, "ArtifactMessage") == 0) {
			s = xmlNodeGetContent(t);
			lasso_assign_string(profile->private_data->artifact_message, (char*)s);
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
}

static void
finalize(GObject *object)
{
	LassoProfile *profile = LASSO_PROFILE(object);
	lasso_release(profile->private_data);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoProfile *profile)
{
	profile->private_data = g_new0(LassoProfilePrivate, 1);
	profile->private_data->dispose_has_run = FALSE;
	profile->private_data->artifact = NULL;
	profile->private_data->artifact_message = NULL;

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
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;

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
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoProfile", &this_info, 0);
	}
	return this_type;
}

