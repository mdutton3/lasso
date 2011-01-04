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
 * SECTION:session
 * @short_description: Principal Session
 *
 **/

#include "../xml/private.h"
#include "../lasso_config.h"
#include "session.h"
#include "sessionprivate.h"
#include "../xml/saml_assertion.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../utils.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>

#ifdef LASSO_WSF_ENABLED
#include "../id-wsf-2.0/sessionprivate.h"
#endif

/*****************************************************************************/
/* public methods	                                                     */
/*****************************************************************************/

static gint
lasso_session_add_assertion_simple(LassoSession *session, const char *providerID, LassoNode
		*assertion)
{
	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(providerID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(assertion != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	g_hash_table_insert(session->assertions, g_strdup(providerID),
			g_object_ref(assertion));

    return 0;
}

/**
 * lasso_session_add_assertion:
 * @session: a #LassoSession
 * @providerID: the provider ID
 * @assertion: the assertion
 *
 * Adds @assertion to the principal session. This function also
 * add the assertion to the index by assertionID.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_add_assertion(LassoSession *session, const char *providerID, LassoNode *assertion)
{
	gint ret = 0;

	ret = lasso_session_add_assertion_simple(session, providerID, assertion);
	if (ret != 0) {
		return ret;
	}

	/* ID-WSF specific need */
	if (LASSO_IS_SAML_ASSERTION(assertion)) {
		LassoSamlAssertion *saml_assertion = LASSO_SAML_ASSERTION(assertion);
		if (saml_assertion->Advice) {
			LassoSamlAdvice *advice = saml_assertion->Advice;
			LassoSamlAssertion *advice_assertion = (LassoSamlAssertion*)advice->Assertion;
			if (LASSO_IS_SAML_ASSERTION(advice_assertion)) {
				xmlNode *node = lasso_node_get_original_xmlnode(&advice_assertion->parent);
				if (xmlSecCheckNodeName(node, (xmlChar*)"Assertion", (xmlChar*)LASSO_SAML_ASSERTION_HREF)) {
					xmlChar *id = xmlGetProp(node, (xmlChar*)"AssertionID");
					ret = lasso_session_add_assertion_with_id(session, (char*)id, node);
					xmlFree(id);
				}
			}
		}
	}

	session->is_dirty = TRUE;

	return ret;
}

/**
 * lasso_session_add_assertion_with_id:
 * @session: a #LassoSession
 * @assertionID: the provider ID
 * @assertion: the assertion
 *
 * Adds an assertion to the dictionnary of assertion indexed by their id,
 * do not store a reference by the Issuer like #lasso_session_add_assertion.
 *
 * Returns: 0 if the assertion was added to the dictionnary.
 */
gint
lasso_session_add_assertion_with_id(LassoSession *session, const char *assertionID,
	xmlNode *assertion)
{
	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(assertionID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(assertion != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	g_hash_table_insert(session->private_data->assertions_by_id,
			g_strdup(assertionID),
			xmlCopyNode(assertion, 1));

	session->is_dirty = TRUE;

	return 0;
}

/**
 * lasso_session_add_status:
 * @session: a #LassoSession
 * @providerID: the provider ID
 * @status: the status
 *
 * Adds @status to the principal session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_add_status(LassoSession *session, const char *providerID, LassoNode *status)
{
	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(providerID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(status != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	g_hash_table_insert(session->private_data->status, g_strdup(providerID), status);

	session->is_dirty = TRUE;

	return 0;
}


/**
 * lasso_session_get_assertion
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Gets the assertion for the given @providerID.
 *
 * Return value:(transfer none)(allow-none): the assertion or NULL if it didn't exist.  This
 *      #LassoSamlAssertion is internally allocated and must not be freed by
 *      the caller.
 **/
LassoNode*
lasso_session_get_assertion(LassoSession *session, const gchar *providerID)
{
	g_return_val_if_fail(LASSO_IS_SESSION(session), NULL);

	return g_hash_table_lookup(session->assertions, providerID);
}

/**
 * lasso_session_get_assertion_by_id:
 * @session: a #LassoSession
 * @assertionID: the assertionID of the requested assertion
 *
 * Gets the assertion for the given @assertionID.
 *
 * Return value:(transfer none)(allow-none): the assertion or NULL if it didn't exist.  This
 *      #LassoSamlAssertion is internally allocated and must not be freed by
 *      the caller.
 */
xmlNode*
lasso_session_get_assertion_by_id(LassoSession *session, const gchar *assertionID)
{
	g_return_val_if_fail(LASSO_IS_SESSION(session), NULL);

	return g_hash_table_lookup(session->private_data->assertions_by_id, assertionID);
}

static void
add_assertion_to_list(G_GNUC_UNUSED gchar *key, LassoLibAssertion *value, GList **list)
{
	*list = g_list_append(*list, value);
}

/**
 * lasso_session_get_assertions
 * @session: a #LassoSession
 * @provider_id: the provider ID
 *
 * Gets the assertions for the given @provider_id.
 *
 * Return value:(allow-none)(transfer container) (element-type LassoNode): a list of #LassoSamlAssertion.
 **/
GList*
lasso_session_get_assertions(LassoSession *session, const char *provider_id)
{
	GList *r = NULL;
	LassoSamlAssertion *assertion;

	if (session == NULL) {
		return NULL;
	}

	if (provider_id == NULL) {
		g_hash_table_foreach(session->assertions, (GHFunc)add_assertion_to_list, &r);
	} else {
		assertion = g_hash_table_lookup(session->assertions, provider_id);
		if (assertion)
			r = g_list_append(r, assertion);
	}
	return r;
}


/**
 * lasso_session_get_status
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Gets the status for the given @providerID.
 *
 * Return value:(transfer none)(allow-none): the status or NULL if it didn't exist.  This #LassoSamlpStatus
 *      is internally allocated and must not be freed by the caller.
 **/
LassoNode*
lasso_session_get_status(LassoSession *session, const gchar *providerID)
{
	if (session == NULL) {
		return NULL;
	}
	return g_hash_table_lookup(session->private_data->status, providerID);
}

static void
add_providerID(gchar *key, G_GNUC_UNUSED LassoLibAssertion *assertion, LassoSession *session)
{
	lasso_list_add_string(session->private_data->providerIDs, key);
}

/**
 * lasso_session_get_provider_index:
 * @session: a #LassoSession
 * @index: index of requested provider
 *
 * Looks up and returns the nth provider id.
 *
 * Return value:(transfer full)(allow-none): the provider id; or NULL if there were no nth provider.  This
 *      string must be freed by the caller.
 **/
gchar*
lasso_session_get_provider_index(LassoSession *session, gint index)
{
	GList *element;
	int length;

	g_return_val_if_fail(LASSO_IS_SESSION(session), NULL);
	g_return_val_if_fail(session->private_data, NULL);

	length = g_hash_table_size(session->assertions);

	if (length == 0)
		return NULL;

	if (session->private_data->providerIDs == NULL) {
		lasso_session_init_provider_ids(session);
	}

	element = g_list_nth(session->private_data->providerIDs, index);
	if (element == NULL)
		return NULL;

	return g_strdup(element->data);
}


/**
 * lasso_session_init_provider_ids:
 * @session: a #LassoSession
 *
 * Initializes internal assertions providers list, used to iterate in logout
 * process.
 **/
void
lasso_session_init_provider_ids(LassoSession *session)
{
	g_return_if_fail(LASSO_IS_SESSION(session));
	g_return_if_fail(session->private_data);

	lasso_release_list_of_strings(session->private_data->providerIDs);
	g_hash_table_foreach(session->assertions, (GHFunc)add_providerID, session);
}


/**
 * lasso_session_is_empty:
 * @session: a #LassoSession
 *
 * Returns %TRUE if session is empty.
 *
 * Return value: %TRUE if empty
 **/
gboolean
lasso_session_is_empty(LassoSession *session)
{
	if (session == NULL) {
		return TRUE;
	}

	if (g_hash_table_size(session->assertions)) {
		return FALSE;
	}
	if (g_hash_table_size(session->private_data->status)) {
		return FALSE;
	}

	return TRUE;
}

/**
 * lasso_session_count_assertions:
 * @session: a #LassoSession object
 *
 * Return the number of assertion currently recored in the session.
 *
 * Return value: a positive value or -1 if session is an invalid #LassoSession object.
 */
gint
lasso_session_count_assertions(LassoSession *session)
{
	GHashTable *hashtable;

	if (! LASSO_IS_SESSION(session))
		return -1;
	hashtable = session->assertions;

	return hashtable ? g_hash_table_size(hashtable) : 0;
}

gboolean
lasso_session_is_dirty(LassoSession *session)
{
	lasso_return_val_if_invalid_param(SESSION, session, TRUE);

	return session->is_dirty;
}

/**
 * lasso_session_remove_assertion:
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Removes assertion for @providerID from @session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_remove_assertion(LassoSession *session, const gchar *providerID)
{
	if (! LASSO_IS_SESSION(session) || lasso_strisempty(providerID)) {
		return LASSO_PARAM_ERROR_INVALID_VALUE;
	}

	if (g_hash_table_remove(session->assertions, providerID)) {
		session->is_dirty = TRUE;
		return 0;
	}

	return LASSO_PROFILE_ERROR_MISSING_ASSERTION;
}

/**
 * lasso_session_remove_status:
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Removes status for @providerID from @session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_remove_status(LassoSession *session, const gchar *providerID)
{
	g_return_val_if_fail(session != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(providerID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	if (g_hash_table_remove(session->private_data->status, providerID)) {
		session->is_dirty = TRUE;
		return 0;
	}

	return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
}


/*****************************************************************************/
/* private methods	                                                     */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

typedef struct _DumpContext {
	xmlNode *parent;
} DumpContext;

static void
add_assertion_childnode(gchar *key, LassoLibAssertion *value, DumpContext *context)
{
	xmlNode *t;
	xmlNode *xmlnode;

	xmlnode = context->parent;
	t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Assertion", NULL);
	xmlSetProp(t, (xmlChar*)"RemoteProviderID", (xmlChar*)key);
	xmlAddChild(t, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

xmlChar *
xmlNode_to_base64(xmlNode *node) {
	xmlOutputBufferPtr buf = NULL;
	xmlCharEncodingHandlerPtr handler = NULL;
	xmlChar *buffer = NULL;
	xmlChar *ret = NULL;

	handler = xmlFindCharEncodingHandler("utf-8");
	if (! handler)
		goto cleanup;
	buf = xmlAllocOutputBuffer(handler);
	if (! buf)
		goto cleanup;
	xmlNodeDumpOutput(buf, NULL, node, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	buffer = buf->conv ? buf->conv->content : buf->buffer->content;

	ret = xmlSecBase64Encode(buffer, strlen((char*)buffer), 0);

cleanup:
	if (buf)
		xmlOutputBufferClose(buf);

	return ret;
}

static void
add_assertion_by_id(gchar *key, xmlNode *value, DumpContext *context)
{
	xmlNode *t, *xmlnode;
	xmlChar *content;

	xmlnode = context->parent;
	t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Assertion", NULL);
	xmlSetProp(t, (xmlChar*)"ID", (xmlChar*)key);
	content = xmlNode_to_base64(value);
	if (content) {
		// xmlAddChild(t, xmlCopyNode(value, 1));
		xmlNodeSetContent(t, content);
		xmlFree(content);
	}
}

static void
add_status_childnode(gchar *key, LassoSamlpStatus *value, DumpContext *context)
{
	xmlNode *t;
	xmlNode *xmlnode;

	xmlnode = context->parent;
	t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Status", NULL);
	xmlSetProp(t, (xmlChar*)"RemoteProviderID", (xmlChar*)key);
	xmlAddChild(t, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

static xmlNode*
get_xmlNode(LassoNode *node, G_GNUC_UNUSED gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoSession *session = LASSO_SESSION(node);
	DumpContext context;

	xmlnode = xmlNewNode(NULL, (xmlChar*)"Session");
	context.parent = xmlnode;

	xmlSetNs(xmlnode, xmlNewNs(xmlnode, (xmlChar*)LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, (xmlChar*)"Version", (xmlChar*)"2");

	if (g_hash_table_size(session->assertions))
		g_hash_table_foreach(session->assertions,
				(GHFunc)add_assertion_childnode, &context);
	if (g_hash_table_size(session->private_data->status))
		g_hash_table_foreach(session->private_data->status,
				(GHFunc)add_status_childnode, &context);
	if (g_hash_table_size(session->private_data->assertions_by_id)) {
		g_hash_table_foreach(session->private_data->assertions_by_id,
				(GHFunc)add_assertion_by_id, &context);
	}

#ifdef LASSO_WSF_ENABLED
	lasso_session_id_wsf2_dump_eprs(session, xmlnode);
#endif

	return xmlnode;
}

xmlNode*
base64_to_xmlNode(xmlChar *buffer) {
	xmlChar *decoded = NULL;
	xmlDoc *doc = NULL;
	xmlNode *ret = NULL;
	int l1,l2;

	l1 = 4*strlen((char*)buffer)+2;
	decoded = g_malloc(l1);
	l2 = xmlSecBase64Decode(buffer, decoded, l1);
	if (l2 < 0)
		goto cleanup;
	doc = xmlParseMemory((char*)decoded, l2);
	if (doc == NULL)
		goto cleanup;
	ret = xmlDocGetRootElement(doc);
	if (ret) {
	ret = xmlCopyNode(ret, 1);
	}
cleanup:
	lasso_release(decoded);
	lasso_release_doc(doc);

	return ret;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoSession *session = LASSO_SESSION(node);
	xmlNode *t;
	xmlNode *n;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		if (strcmp((char*)t->name, "Assertion") == 0) {
			xmlChar* value;
			n = t->children;
			while (n && n->type != XML_ELEMENT_NODE) n = n->next;

			if (n) {
				LassoNode *assertion;

				if ((value = xmlGetProp(t, (xmlChar*)"RemoteProviderID"))) {

					assertion = lasso_node_new_from_xmlNode(n);
					lasso_session_add_assertion_simple(session, (char*)value, assertion);
					lasso_release_gobject(assertion);
					xmlFree(value);
				}
			} else if ((value = xmlGetProp(t, (xmlChar*)"ID"))) {
				xmlChar *content;
				xmlNode *assertion;

				content = xmlNodeGetContent(t);
				if (content) {
					assertion = base64_to_xmlNode(content);
					if (assertion) {
						lasso_session_add_assertion_with_id(session,
								(char*)value, assertion);
						xmlFreeNode(assertion);
					}
					xmlFree(content);
				}
				xmlFree(value);
			}
		}
		if (strcmp((char*)t->name, "Status") == 0) {
			n = t->children;
			while (n && n->type != XML_ELEMENT_NODE) n = n->next;

			if (n) {
				LassoNode *status;
				status = lasso_node_new_from_xmlNode(n);
				g_hash_table_insert(session->private_data->status,
						xmlGetProp(t, (xmlChar*)"RemoteProviderID"),
						status);
			}
		}

#ifdef LASSO_WSF_ENABLED
	lasso_session_id_wsf2_init_eprs(session, t);
#endif

		t = t->next;
	}
	return 0;
}




/*****************************************************************************/
/* overridden parent class methods	                                     */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoSession *session = LASSO_SESSION(object);

	if (! session->private_data || session->private_data->dispose_has_run == TRUE)
		return;
	session->private_data->dispose_has_run = TRUE;

	lasso_release_ghashtable(session->assertions);
	lasso_release_ghashtable(session->private_data->status);
	lasso_release_list_of_strings(session->private_data->providerIDs);
	lasso_release_ghashtable(session->private_data->assertions_by_id);

#ifdef LASSO_WSF_ENABLED
	lasso_release_ghashtable(session->private_data->eprs);
#endif

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoSession *session = LASSO_SESSION(object);

	lasso_release(session->private_data);
	session->private_data = NULL;

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions	                                 */
/*****************************************************************************/

static void
instance_init(LassoSession *session)
{
	session->private_data = g_new0 (LassoSessionPrivate, 1);
	session->private_data->dispose_has_run = FALSE;
	session->private_data->providerIDs = NULL;
	session->private_data->status = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_node_destroy);
	session->private_data->assertions_by_id =
			g_hash_table_new_full(g_str_hash, g_str_equal,
					(GDestroyNotify)g_free,
					(GDestroyNotify)xmlFree);
#ifdef LASSO_WSF_ENABLED
	session->private_data->eprs = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)g_object_unref);
#endif
	session->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free, (GDestroyNotify)lasso_node_destroy);
	session->is_dirty = FALSE;
}

static void
class_init(LassoSessionClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_session_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSessionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSession),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSession", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_session_new:
 *
 * Creates a new #LassoSession.
 *
 * Return value: a newly created #LassoSession
 **/
LassoSession*
lasso_session_new()
{
	return g_object_new(LASSO_TYPE_SESSION, NULL);
}

/**
 * lasso_session_new_from_dump:
 * @dump: XML server dump
 *
 * Restores the @dump to a new #LassoSession.
 *
 * Return value: a newly created #LassoSession; or NULL if an error occured
 **/
LassoSession*
lasso_session_new_from_dump(const gchar *dump)
{
	LassoSession *session;

	session = (LassoSession*)lasso_node_new_from_dump(dump);
	if (! LASSO_IS_SESSION(session)) {
		lasso_release_gobject(session);
	}
	return session;
}

/**
 * lasso_session_dump:
 * @session: a #LassoSession
 *
 * Dumps @session content to an XML string.
 *
 * Return value:(transfer full): the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_session_dump(LassoSession *session)
{
	if (lasso_session_is_empty(session))
		return g_strdup("");

	return lasso_node_dump(LASSO_NODE(session));
}

/**
 * lasso_session_destroy:
 * @session: a #LassoSession
 *
 * Destroys a session.
 **/
void lasso_session_destroy(LassoSession *session)
{
	if (session == NULL)
		return;
	lasso_node_destroy(LASSO_NODE(session));
}
