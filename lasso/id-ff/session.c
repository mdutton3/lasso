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

/**
 * SECTION:session
 * @short_description: Principal Session
 *
 **/

#include "../xml/private.h"
#include "../lasso_config.h"
#include "session.h"
#include "sessionprivate.h"
#include "../xml/lib_authentication_statement.h"
#include "../xml/saml_assertion.h"
#include "../xml/saml-2.0/saml2_authn_statement.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../utils.h"
#include "../debug.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>

#ifdef LASSO_WSF_ENABLED
#include "../id-wsf-2.0/sessionprivate.h"
#endif

static gboolean lasso_match_name_id(LassoNode *a, LassoNode *b);

struct _NidAndSessionIndex {
	LassoNode *name_id;
	char *assertion_id;
	char *session_index;
};

struct _NidAndSessionIndex *
lasso_new_nid_and_session_index(LassoNode *name_id, const char *assertion_id, const char
		*session_index)
{
	struct _NidAndSessionIndex *nid_and_session_index = g_new0(struct _NidAndSessionIndex, 1);
	lasso_assign_gobject(nid_and_session_index->name_id, name_id);
	lasso_assign_string(nid_and_session_index->assertion_id, assertion_id);
	lasso_assign_string(nid_and_session_index->session_index, session_index);

	return nid_and_session_index;
}

void
lasso_release_nid_and_session_index(struct _NidAndSessionIndex *nid_and_session_index)
{
	lasso_release_gobject(nid_and_session_index->name_id);
	lasso_release_string(nid_and_session_index->session_index);
	lasso_release_string(nid_and_session_index->assertion_id);
}

void
lasso_release_list_of_nid_an_session_index(GList *list)
{
	g_list_foreach(list, (GFunc)lasso_release_nid_and_session_index, NULL);
	g_list_free(list);
}

/*****************************************************************************/
/* public methods	                                                     */
/*****************************************************************************/

static void
lasso_session_add_nid_and_session_index(LassoSession *session,
		const char *providerID,
		struct _NidAndSessionIndex *nid_and_session_index)
{
	GList *l = g_hash_table_lookup(session->private_data->nid_and_session_indexes, providerID);
	GList *i;

	lasso_foreach(i, l) {
		struct _NidAndSessionIndex *other_nid_and_sid = i->data;

		/* do some sharing and limit doublons */
		if (lasso_match_name_id(other_nid_and_sid->name_id, nid_and_session_index->name_id)) {
			if (lasso_strisequal(other_nid_and_sid->session_index, nid_and_session_index->session_index)) {
				lasso_release_nid_and_session_index(nid_and_session_index);
				return;
			}
			// lasso_assign_gobject(nid_and_session_index->name_id, other_nid_and_sid->name_id);
		}
	}
	if (l) {
		l = g_list_append(l, nid_and_session_index);
	} else {
		l = g_list_append(l, nid_and_session_index);
		g_hash_table_insert(session->private_data->nid_and_session_indexes,
				g_strdup(providerID), l);
	}
}

/**
 * lasso_session_add_assertion_nid_and_session_index:
 *
 * Extract NameID and SessionIndex and keep them around.
 *
 */
static gint
lasso_session_add_assertion_nid_and_session_index(LassoSession *session, const gchar *providerID,
		LassoNode *assertion)
{
	struct _NidAndSessionIndex *nid_and_session_index = NULL;

	lasso_bad_param(SESSION, session);
	lasso_null_param(assertion);

	if (LASSO_IS_SAML_ASSERTION(assertion)) { /* saml 1.1 */
		LassoSamlAssertion *saml_assertion = (LassoSamlAssertion*) assertion;
		LassoLibAuthenticationStatement *auth_statement = NULL;
		LassoSamlSubjectStatementAbstract *ss = NULL;

		if (saml_assertion->SubjectStatement)
			ss = &saml_assertion->SubjectStatement->parent;
		else if (saml_assertion->AuthenticationStatement)
			ss = &saml_assertion->AuthenticationStatement->parent;
		else
			return LASSO_PARAM_ERROR_INVALID_VALUE;
		if (! ss->Subject)
			return LASSO_PARAM_ERROR_INVALID_VALUE;
		if (! ss->Subject->NameIdentifier)
			return LASSO_PARAM_ERROR_INVALID_VALUE;
		if (! LASSO_IS_LIB_AUTHENTICATION_STATEMENT(saml_assertion->AuthenticationStatement))
			return LASSO_ERROR_UNIMPLEMENTED;
		auth_statement = (LassoLibAuthenticationStatement*)
			saml_assertion->AuthenticationStatement;
		if (! auth_statement->SessionIndex)
			return 0;
		nid_and_session_index = lasso_new_nid_and_session_index(
				(LassoNode*)ss->Subject->NameIdentifier,
				saml_assertion->AssertionID,
				auth_statement->SessionIndex);
		lasso_session_add_nid_and_session_index(session,
				providerID, nid_and_session_index);
	} else if (LASSO_IS_SAML2_ASSERTION(assertion)) { /* saml 2.0 */
		LassoSaml2Assertion *saml2_assertion = (LassoSaml2Assertion*) assertion;
		GList *iter;

		if (! saml2_assertion->Subject)
			return LASSO_PARAM_ERROR_INVALID_VALUE;
		if (! saml2_assertion->Subject->NameID)
			return LASSO_PARAM_ERROR_INVALID_VALUE;
		if (! saml2_assertion->AuthnStatement)
			return 0;
		lasso_foreach(iter, saml2_assertion->AuthnStatement) {
			LassoSaml2AuthnStatement *authn_statement = iter->data;

			if (authn_statement->SessionIndex) {
				nid_and_session_index = lasso_new_nid_and_session_index(
						(LassoNode*)saml2_assertion->Subject->NameID,
						saml2_assertion->ID,
						authn_statement->SessionIndex);
				lasso_session_add_nid_and_session_index(session,
						providerID,
						nid_and_session_index);
			}
		}
	} else {
		return LASSO_ERROR_UNIMPLEMENTED;
	}
	return 0;
}

static gint
lasso_session_add_assertion_simple(LassoSession *session, const char *providerID, LassoNode
		*assertion)
{
	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(providerID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(assertion != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	if (lasso_flag_thin_sessions) { /* do not store the full assertion */
		return 0;
	}
	g_hash_table_insert(session->assertions, g_strdup(providerID),
			g_object_ref(assertion));

    return 0;
}

static gboolean
lasso_match_name_id(LassoNode *a, LassoNode *b)
{
	if (LASSO_IS_SAML_NAME_IDENTIFIER(a) && LASSO_IS_SAML_NAME_IDENTIFIER(b)) {
		return lasso_saml_name_identifier_equals((LassoSamlNameIdentifier*)a,
					(LassoSamlNameIdentifier*)b);

	} else if (LASSO_IS_SAML2_NAME_ID(a) && LASSO_IS_SAML2_NAME_ID(b)) {
		return lasso_saml2_name_id_equals((LassoSaml2NameID*)a,
					(LassoSaml2NameID*)b);
	}
	return FALSE;
}

/**
 * lasso_session_get_session_indexes:
 * @session: a #LassoSession object
 * @providerID: a provider id
 * @name_id: a #LassoSamlAssertion or #LassoSaml2Assertion object
 *
 * Gets all the registered session indexes for this session.
 *
 * Return value:(transfer full)(element-type utf8): a list of string containing the session index identifiers.
 */
GList*
lasso_session_get_session_indexes(LassoSession *session,
		const gchar *providerID,
		LassoNode *node)
{
	GList *l = NULL, *iter = NULL;
	GList *ret = NULL;

	if (! LASSO_IS_SESSION(session))
		return NULL;
	if (! providerID)
		return NULL;
	l = g_hash_table_lookup(session->private_data->nid_and_session_indexes,
			providerID);

	lasso_foreach(iter, l) {
		struct _NidAndSessionIndex *nid_and_session_index = iter->data;

		if (! nid_and_session_index->session_index)
			continue;

		if (node && ! lasso_match_name_id(node, nid_and_session_index->name_id)) {
			continue;
		}
		lasso_list_add_string(ret, nid_and_session_index->session_index);
	}
	return ret;
}

/**
 * lasso_session_get_name_ids:
 * @session: a #LassoSession object
 * @providerID: a provider identifier
 *
 * List the known NameID coming from this provider during this session.
 *
 * Return value:(transfer full)(element-type LassoNode): a list of #LassoNode objects.
 */
GList*
lasso_session_get_name_ids(LassoSession *session, const gchar *providerID)
{
	GList *nid_and_session_indexes = NULL;
	GList *ret = NULL;
	GList *i, *j;

	if (! LASSO_IS_SESSION(session))
		return NULL;

	if (! providerID)
		return NULL;

	nid_and_session_indexes = g_hash_table_lookup(session->private_data->nid_and_session_indexes,
			providerID);

	lasso_foreach(i, nid_and_session_indexes) {
		struct _NidAndSessionIndex *nid_and_session_index = i->data;
		int ok = 1;

		lasso_foreach(j, ret) {
			if (lasso_match_name_id(j->data, nid_and_session_index->name_id)) {
				ok = 0;
				break;
			}
		}
		if (ok) {
			lasso_list_add_gobject(ret, nid_and_session_index->name_id);
		}
	}
	return ret;
}

/**
 * lasso_session_get_assertion_ids:
 * @session: a #LassoSession object
 * @providerID: a provider identifier
 *
 * List the ids of assertions received during the current session.
 *
 * Return value:(transfer full)(element-type utf8): a list of strings
 */
GList*
lasso_session_get_assertion_ids(LassoSession *session, const gchar *providerID)
{
	GList *nid_and_session_indexes = NULL;
	GList *ret = NULL;
	GList *i;

	if (! LASSO_IS_SESSION(session))
		return NULL;

	if (! providerID)
		return NULL;

	nid_and_session_indexes = g_hash_table_lookup(session->private_data->nid_and_session_indexes,
			providerID);

	lasso_foreach(i, nid_and_session_indexes) {
		struct _NidAndSessionIndex *nid_and_session_index = i->data;
		lasso_list_add_string(ret, nid_and_session_index->assertion_id);
	}
	return ret;
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
	ret = lasso_session_add_assertion_nid_and_session_index(session, providerID, assertion);
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
add_providerID(gchar *key, G_GNUC_UNUSED struct _NidAndSessionIndex *ignored, LassoSession *session)
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

	length = g_hash_table_size(session->private_data->nid_and_session_indexes);

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
	g_hash_table_foreach(session->private_data->nid_and_session_indexes, (GHFunc)add_providerID,
			session);
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

	if (g_hash_table_size(session->assertions) +
	    g_hash_table_size(session->private_data->status) +
	    g_hash_table_size(session->private_data->assertions_by_id) +
	    g_hash_table_size(session->private_data->nid_and_session_indexes))
	{
		return FALSE;
	}
#ifdef LASSO_WSF_ENABLED
	if (g_hash_table_size(session->eprs)) {
		return FALSE;
	}
#endif

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
	if (lasso_flag_thin_sessions)
		hashtable = session->private_data->nid_and_session_indexes;
	else
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
	int rc = 0;
	gboolean ok1, ok2;

	lasso_bad_param(SESSION, session);
	lasso_return_val_if_fail(! lasso_strisempty(providerID), LASSO_PARAM_ERROR_INVALID_VALUE);

	ok1 = g_hash_table_remove(session->assertions, providerID);
	ok2 = g_hash_table_remove(session->private_data->nid_and_session_indexes, providerID);

	if (ok1 || ok2) {
		session->is_dirty = TRUE;
	} else {
		rc = LASSO_PROFILE_ERROR_MISSING_ASSERTION;
	}
	return rc;
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
	gchar *buffer = NULL;
	xmlChar *ret = NULL;

	buffer = lasso_xmlnode_to_string(node, 0, 0);
	ret = xmlSecBase64Encode(BAD_CAST buffer, strlen((char*)buffer), 0);
	lasso_release_string(buffer);
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

#define NID_AND_SESSION_INDEX "NidAndSessionIndex"
#define SESSION_INDEX "SessionIndex"
#define PROVIDER_ID "ProviderID"
#define ASSERTION_ID "AssertionID"

static void
xmlnode_add_assertion_nid_and_session_indexes(gchar *key, GList *nid_and_session_indexes, DumpContext *context)
{
	GList *iter;

	if (! nid_and_session_indexes) {
		return;
	}
	lasso_foreach(iter, nid_and_session_indexes) {
		struct _NidAndSessionIndex *nid_and_session_index = iter->data;
		xmlNode *node = xmlSecAddChild(context->parent, BAD_CAST NID_AND_SESSION_INDEX,
				BAD_CAST LASSO_LASSO_HREF);

		xmlSetProp(node, BAD_CAST PROVIDER_ID, BAD_CAST key);
		xmlSetProp(node, BAD_CAST ASSERTION_ID, BAD_CAST nid_and_session_index->assertion_id);
		if (nid_and_session_index->session_index) {
			xmlSetProp(node, BAD_CAST SESSION_INDEX,
					BAD_CAST nid_and_session_index->session_index);
		}
		xmlSecAddChildNode(node, lasso_node_get_xmlNode(nid_and_session_index->name_id,
					FALSE));
	}
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
	if (g_hash_table_size(session->private_data->nid_and_session_indexes)) {
		g_hash_table_foreach(session->private_data->nid_and_session_indexes,
				(GHFunc)xmlnode_add_assertion_nid_and_session_indexes, &context);
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

static void
init_from_xml_nid_and_session_index(LassoNode *node, xmlNode *nid_and_session_index_node)
{
	xmlChar *session_index = NULL;
	xmlChar *provider_id = NULL;
	xmlChar *assertion_id = NULL;
	xmlNode *nid;
	LassoNode *name_id;
	struct _NidAndSessionIndex *nid_and_session_index;

	provider_id = xmlGetProp(nid_and_session_index_node, BAD_CAST PROVIDER_ID);
	if (! provider_id)
		goto cleanup;
	assertion_id = xmlGetProp(nid_and_session_index_node, BAD_CAST ASSERTION_ID);
	if (! assertion_id)
		goto cleanup;
	nid = xmlSecGetNextElementNode(nid_and_session_index_node->children);
	if (! nid)
		goto cleanup;
	name_id = lasso_node_new_from_xmlNode(nid);
	if (! name_id)
		goto cleanup;
	session_index = xmlGetProp(nid_and_session_index_node, BAD_CAST SESSION_INDEX);
	nid_and_session_index = lasso_new_nid_and_session_index(name_id, (char*)assertion_id,
			(char*)session_index);
	lasso_session_add_nid_and_session_index((LassoSession*)node, (char*)provider_id,
			nid_and_session_index);
cleanup:
	lasso_release_xml_string(session_index);
	lasso_release_xml_string(provider_id);
	lasso_release_xml_string(assertion_id);
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
					/* automatic upgrade from old session serialization to the new */
					lasso_session_add_assertion_nid_and_session_index(session, (char*)value, assertion);
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
		if (xmlSecCheckNodeName(t, BAD_CAST NID_AND_SESSION_INDEX,
					BAD_CAST LASSO_LASSO_HREF)) {
			init_from_xml_nid_and_session_index(node, t);
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
	lasso_release_ghashtable(session->private_data->nid_and_session_indexes);

#ifdef LASSO_WSF_ENABLED
	lasso_release_ghashtable(session->private_data->eprs);
#endif

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

/*****************************************************************************/
/* instance and class init functions	                                 */
/*****************************************************************************/

static void
instance_init(LassoSession *session)
{
	session->private_data = LASSO_SESSION_GET_PRIVATE(session);
	session->private_data->dispose_has_run = FALSE;
	session->private_data->providerIDs = NULL;
	session->private_data->status = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_node_destroy);
	session->private_data->assertions_by_id =
			g_hash_table_new_full(g_str_hash, g_str_equal,
					(GDestroyNotify)g_free,
					(GDestroyNotify)xmlFree);
	session->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free, (GDestroyNotify)lasso_node_destroy);
	session->is_dirty = FALSE;
	session->private_data->nid_and_session_indexes = g_hash_table_new_full(g_str_hash,
			g_str_equal, (GDestroyNotify)g_free,
			(GDestroyNotify)lasso_release_list_of_nid_an_session_index);
#ifdef LASSO_WSF_ENABLED
	session->private_data->eprs = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)g_object_unref);
#endif
}

static void
class_init(LassoSessionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);
	parent_class = g_type_class_peek_parent(klass);

	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Session");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	g_type_class_add_private(nclass, sizeof(LassoSessionPrivate));

	G_OBJECT_CLASS(klass)->dispose = dispose;
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

gboolean
lasso_session_has_slo_session(LassoSession *session, const gchar *provider_id)
{
	if (! LASSO_IS_SESSION(session))
		return FALSE;
	return g_hash_table_lookup(session->private_data->nid_and_session_indexes, provider_id) !=
		NULL;
}
