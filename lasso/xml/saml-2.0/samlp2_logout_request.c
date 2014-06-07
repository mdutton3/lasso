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

#include "../private.h"
#include "../../utils.h"
#include "samlp2_logout_request.h"
#include <libxml/tree.h>
#include <xmlsec/xmltree.h>

/**
 * SECTION:samlp2_logout_request
 * @short_description: &lt;samlp2:LogoutRequest&gt;
 *
 * <figure><title>Schema fragment for samlp2:LogoutRequest</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="LogoutRequestType">
 *   <complexContent>
 *     <extension base="samlp:RequestAbstractType">
 *       <sequence>
 *         <choice>
 *           <element ref="saml:BaseID"/>
 *           <element ref="saml:NameID"/>
 *           <element ref="saml:EncryptedID"/>
 *         </choice>
 *         <element ref="samlp:SessionIndex" minOccurs="0" maxOccurs="unbounded"/>
 *       </sequence>
 *       <attribute name="Reason" type="string" use="optional"/>
 *       <attribute name="NotOnOrAfter" type="dateTime" use="optional"/>
 *     </extension>
 *   </complexContent>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

typedef struct _LassoSamlp2LogoutRequestPrivate LassoSamlp2LogoutRequestPrivate;

struct _LassoSamlp2LogoutRequestPrivate {
	GList *SessionIndex;
};

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "BaseID", SNIPPET_NODE | SNIPPET_JUMP_ON_MATCH | SNIPPET_JUMP_3, G_STRUCT_OFFSET(LassoSamlp2LogoutRequest, BaseID), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "NameID", SNIPPET_NODE | SNIPPET_JUMP_ON_MATCH | SNIPPET_JUMP_2, G_STRUCT_OFFSET(LassoSamlp2LogoutRequest, NameID), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "EncryptedID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlp2LogoutRequest, EncryptedID), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "SessionIndex", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSamlp2LogoutRequest, SessionIndex), NULL, NULL, NULL},
	{ "SessionIndex", SNIPPET_LIST_NODES,
		0, NULL, NULL, NULL},
	{ "Reason", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2LogoutRequest, Reason), NULL, NULL, NULL},
	{ "NotOnOrAfter", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2LogoutRequest, NotOnOrAfter), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

#define SESSION_INDEX "SessionIndex"

#define GET_PRIVATE(x) G_TYPE_INSTANCE_GET_PRIVATE(x, \
		LASSO_TYPE_SAMLP2_LOGOUT_REQUEST, LassoSamlp2LogoutRequestPrivate)

static void
dispose(GObject *object)
{
	LassoSamlp2LogoutRequest *logout_request = LASSO_SAMLP2_LOGOUT_REQUEST(object);
	LassoSamlp2LogoutRequestPrivate *pv;

	pv = GET_PRIVATE(logout_request);
	lasso_release_list_of_strings(pv->SessionIndex);
	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(logout_request));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

/* GROSS HACK: in order to support multiple session index elements, we use a private field that is
 * directly parsed or serialized through the overloaded get_xmlNode and init_from_xml virtual
 * methods.  The structure of LassoSamlp2LogoutRequest is part, until the next major release, of our
 * public ABI, so we cound not do otherwise.
 *
 * The last parsed element is kept in the legacy field logout_request->SessionIndex. At parsing and
 * serializing time it is separated from other elements. This should keep the old behaviour intact.
 */
static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	GList *other_session_index, *it;
	char *keep_session_index;

	other_session_index = lasso_samlp2_logout_request_get_session_indexes((LassoSamlp2LogoutRequest*)node);
	/* save SessionIndex simple field, and nullify it */
	keep_session_index = ((LassoSamlp2LogoutRequest*)node)->SessionIndex;
	((LassoSamlp2LogoutRequest*)node)->SessionIndex = NULL;
	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	lasso_foreach(it, other_session_index) {
		xmlNode *child = xmlSecAddChild(xmlnode, BAD_CAST SESSION_INDEX,
				BAD_CAST LASSO_SAML2_PROTOCOL_HREF);
#if (XMLSEC_MAJOR > 1) || (XMLSEC_MAJOR == 1 && XMLSEC_MINOR > 2) || (XMLSEC_MAJOR == 1 && XMLSEC_MINOR == 2 && XMLSEC_SUBMINOR > 12)
		xmlSecNodeEncodeAndSetContent(child, BAD_CAST it->data);
#else
		xmlChar *content;
		content = xmlEncodeSpecialChars(child->doc, BAD_CAST it->data);
		xmlNodeSetContent(child, content);
		xmlFree(content);
#endif
	}
	((LassoSamlp2LogoutRequest*)node)->SessionIndex = keep_session_index;
	lasso_release_list_of_strings(other_session_index);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc = 0;
	xmlNode *child = NULL;
	LassoSamlp2LogoutRequestPrivate *pv = NULL;
	LassoSamlp2LogoutRequest *logout_request = (LassoSamlp2LogoutRequest*)node;

	rc = parent_class->init_from_xml(node, xmlnode);
	if ((logout_request->BaseID != 0) +
	    (logout_request->NameID != 0) +
	    (logout_request->EncryptedID != 0) != 1) {
		error("samlp2:LogoutRequest needs one of BaseID, NameID or EncryptedID");
		rc = 1;
	}

	if (rc == 0) {

		pv = GET_PRIVATE(node);
		child = xmlSecFindChild(xmlnode, BAD_CAST SESSION_INDEX,
				BAD_CAST LASSO_SAML2_PROTOCOL_HREF);
		while (child && xmlSecCheckNodeName(child, BAD_CAST SESSION_INDEX,
					BAD_CAST LASSO_SAML2_PROTOCOL_HREF)) {
			xmlChar *content = xmlNodeGetContent(child);
			lasso_list_add_string(pv->SessionIndex, (char*) content);
			lasso_release_xml_string(content);
			child = xmlSecGetNextElementNode(child->next);
		}
		/* remove the first one, since it is also stored in node->SessionIndex */
		if (pv->SessionIndex) {
			lasso_release_string(pv->SessionIndex->data);
			pv->SessionIndex = g_list_delete_link(pv->SessionIndex, pv->SessionIndex);
		}
	}

	return rc;
}

static void
class_init(LassoSamlp2LogoutRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	klass->parent.parent.init_from_xml = init_from_xml;
	klass->parent.parent.get_xmlNode = get_xmlNode;
	lasso_node_class_set_nodename(nclass, "LogoutRequest");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(G_OBJECT_CLASS(klass), sizeof(LassoSamlp2LogoutRequestPrivate));
	G_OBJECT_CLASS(klass)->dispose = dispose;
}

GType
lasso_samlp2_logout_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2LogoutRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2LogoutRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_REQUEST_ABSTRACT,
				"LassoSamlp2LogoutRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_logout_request_get_session_indexes:
 * @logout_request: a #LogoutRequest object
 *
 * If the logout request contains more than one SessionIndex element, this method must be used to
 * retrieve due to historical circonstances. It will a return a list of the content of the
 * SessionIndex elements.
 *
 * Return value:(element-type utf8)(transfer full):  a #GList of sessions index.
 */
GList*
lasso_samlp2_logout_request_get_session_indexes(LassoSamlp2LogoutRequest *logout_request)
{
	GList *ret = NULL;
	LassoSamlp2LogoutRequestPrivate *pv = NULL;
	g_return_val_if_fail(LASSO_IS_SAMLP2_LOGOUT_REQUEST(logout_request), NULL);

	/* Return concatenation of old field + new private field */
	pv = GET_PRIVATE(logout_request);
	lasso_assign_list_of_strings(ret, pv->SessionIndex);
	if (logout_request->SessionIndex) {
		ret = g_list_prepend(ret, g_strdup(logout_request->SessionIndex));
	}
	return ret;
}

/**
 * lasso_samlp2_logout_request_set_session_indexes:
 * @logout_request: a #LogoutRequest object
 * @session_index:(element-type utf8): a list of session index
 *
 * If you want to set more than one SessionIndex on a LogoutRequest, use this method. Beware that
 * the public field named SessionIndex corresponds to the last element in this list. This is an
 * symptom of the way elements are parsed by Lasso.
 *
 */
void
lasso_samlp2_logout_request_set_session_indexes(LassoSamlp2LogoutRequest *logout_request,
		GList *session_index)
{
	LassoSamlp2LogoutRequestPrivate *pv;

	g_return_if_fail(LASSO_IS_SAMLP2_LOGOUT_REQUEST(logout_request));

	/* assign rest of the list to the new private field */
	pv = GET_PRIVATE(logout_request);
	lasso_assign_list_of_strings(pv->SessionIndex, session_index);
	/* extract last element and assign it to old field */
	if (pv->SessionIndex && pv->SessionIndex->next) {
		GList *last = g_list_last(pv->SessionIndex);
		lasso_assign_new_string(logout_request->SessionIndex, (char*) last->data);
		pv->SessionIndex = g_list_delete_link(pv->SessionIndex, last);
	}
}

/**
 * lasso_samlp2_logout_request_new:
 *
 * Creates a new #LassoSamlp2LogoutRequest object.
 *
 * Return value: a newly created #LassoSamlp2LogoutRequest object
 **/
LassoNode*
lasso_samlp2_logout_request_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_LOGOUT_REQUEST, NULL);
}
