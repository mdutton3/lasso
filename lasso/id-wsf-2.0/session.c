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
 * SECTION:idwsf2-session-extension
 */
#include "session.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "../utils.h"
#include "../id-ff/session.h"
#include "../id-ff/sessionprivate.h"
#include "../xml/misc_text_node.h"
#include "../xml/ws/wsa_endpoint_reference.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/id-wsf-2.0/disco_svc_metadata.h"
#include "../xml/id-wsf-2.0/disco_service_type.h"
#include "../xml/id-wsf-2.0/disco_security_context.h"
#include "../xml/id-wsf-2.0/sec_token.h"


typedef struct _DumpContext {
	xmlNode *parent;
} DumpContext;

/**
 * lasso_session_add_endpoint_reference:
 * @session: a #LassoSession object
 * @epr: a #LassoWsAddrEndpointReference object
 *
 * Add an endpoint reference to a session object.
 *
 * Return value: 0 if successfull, an error code otherwise.
 */
gint
lasso_session_add_endpoint_reference(LassoSession *session, LassoWsAddrEndpointReference *epr)
{
	GList *i;

	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(LASSO_IS_WSA_ENDPOINT_REFERENCE(epr), LASSO_PARAM_ERROR_INVALID_VALUE);

	for (i = g_list_first(epr->Metadata->any); i != NULL; i = g_list_next(i)) {
		if (LASSO_IS_IDWSF2_DISCO_SERVICE_TYPE(i->data)) {
			g_hash_table_insert(session->private_data->eprs,
				g_strdup(LASSO_IDWSF2_DISCO_SERVICE_TYPE(i->data)->content),
				g_object_ref(epr));
			session->is_dirty = TRUE;
			break;
		}
	}

	return 0;
}

/**
 * lasso_session_get_endpoint_reference:
 * @session: a #LassoSession object
 * @service_type: a string giving the service type.
 *
 * Return an endpoint reference for the given service type.
 *
 * Return value: a caller owned #LassoWsAddrEndpointReference object for the given service type if
 * one is found, NULL otherwise.
 */
LassoWsAddrEndpointReference*
lasso_session_get_endpoint_reference(LassoSession *session, const gchar *service_type)
{
	LassoWsAddrEndpointReference* epr;

	if (! LASSO_IS_SESSION(session) || service_type == NULL)
		return NULL;

	epr = g_hash_table_lookup(session->private_data->eprs, service_type);
	if (LASSO_IS_WSA_ENDPOINT_REFERENCE(epr)) {
		return (LassoWsAddrEndpointReference*)g_object_ref(epr);
	} else {
		return NULL;
	}
}

/**
 * lasso_session_get_assertion_identity_token:
 * @session: a #LassoSession object
 * @service_type: a char* string describing the targeted service
 *
 * Return a security token to contact a specified service.
 *
 * Return value: (allow-none): a #LassoAssertion object or NULL
 */
LassoSaml2Assertion*
lasso_session_get_assertion_identity_token(LassoSession *session, const gchar *service_type)
{
	LassoWsAddrEndpointReference* epr;
	GList *metadata_item;
	GList *i;
	LassoIdWsf2DiscoSecurityContext *security_context;
	LassoIdWsf2SecToken *sec_token;
	LassoSaml2Assertion *assertion = NULL;

	if (LASSO_IS_SESSION(session) == FALSE) {
		return NULL;
	}

	epr = lasso_session_get_endpoint_reference(session, service_type);
	if (epr == NULL || epr->Metadata == NULL) {
		return NULL;
	}

	metadata_item = epr->Metadata->any;
	for (i = g_list_first(metadata_item); i != NULL; i = g_list_next(i)) {
		if (LASSO_IS_IDWSF2_DISCO_SECURITY_CONTEXT(i->data)) {
			security_context = LASSO_IDWSF2_DISCO_SECURITY_CONTEXT(i->data);
			if (security_context->Token != NULL) {
				sec_token = security_context->Token->data;
				if (LASSO_IS_SAML2_ASSERTION(sec_token->any)) {
					lasso_assign_gobject(assertion, sec_token->any);
					break;
				}
			}
		}
	}

	return assertion;
}

void
lasso_session_id_wsf2_init_eprs(LassoSession *session, xmlNode *t)
{
	xmlNode *t2;

	/* Endpoint References */
	if (strcmp((char*)t->name, "EndpointReferences") == 0) {
		t2 = t->children;
		while (t2) {
			LassoWsAddrEndpointReference *epr;
			if (t2->type != XML_ELEMENT_NODE) {
				t2 = t2->next;
				continue;
			}
			epr = LASSO_WSA_ENDPOINT_REFERENCE(
					lasso_wsa_endpoint_reference_new());
			LASSO_NODE_GET_CLASS(epr)->init_from_xml(LASSO_NODE(epr), t2);
			lasso_session_add_endpoint_reference(session, epr);
			g_object_unref(epr);
			t2 = t2->next;
		}
	}
}

static void
add_childnode_from_hashtable(G_GNUC_UNUSED gchar *key, LassoNode *value, DumpContext *context)
{
	xmlNode *xmlnode;

	xmlnode = context->parent;
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

void
lasso_session_id_wsf2_dump_eprs(LassoSession *session, xmlNode *xmlnode) {
	xmlNode *t;
	DumpContext context;

	/* Endpoint References */
	if (session->private_data->eprs != NULL
			&& g_hash_table_size(session->private_data->eprs)) {
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"EndpointReferences", NULL);
		context.parent = t;
		g_hash_table_foreach(session->private_data->eprs,
				(GHFunc)add_childnode_from_hashtable, &context);
	}
}
