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

#include "private.h"
#include "dst_modify_response.h"
#include "idwsf_strings.h"

/**
 * SECTION:dst_modify_response
 * @short_description: &lt;dst:ModifyResponse&gt;
 *
 * <figure><title>Schema fragment for dst:ModifyResponse</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="ModifyResponse" type="ResponseType"/>
 * <xs:complexType name="ResponseType">
 *     <xs:sequence>
 *         <xs:element ref="Status"/>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *     </xs:sequence>
 *     <xs:attribute name="id" type="xs:ID"/>
 *     <xs:attribute name="itemIDRef" type="IDReferenceType"/>
 *     <xs:attribute name="timeStamp" type="xs:dateTime"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModifyResponse, Status), NULL, NULL, NULL},
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoDstModifyResponse, Extension), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModifyResponse, id), NULL, NULL, NULL},
	{ "itemIDRef", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModifyResponse, itemIDRef), NULL, NULL, NULL},
	{ "timeStamp", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModifyResponse, timeStamp), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	xmlNode *t = xmlnode->children;

	xmlSetNs(xmlnode, ns);
	while (t) {
		if (t->type == XML_ELEMENT_NODE && t->ns == NULL)
			insure_namespace(t, ns);
		t = t->next;
	}
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	xmlNs *ns;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_DST_MODIFY_RESPONSE(node)->hrefServiceType,
			(xmlChar*)LASSO_DST_MODIFY_RESPONSE(node)->prefixServiceType);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc = 0;
	LassoDstModifyResponse *response = LASSO_DST_MODIFY_RESPONSE(node);

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	response->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
	response->prefixServiceType = lasso_get_prefix_for_dst_service_href(
			response->hrefServiceType);
	if (response->prefixServiceType == NULL) {
		/* XXX: what to do here ? */
	}

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDstModifyResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "ModifyResponse");
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_dst_modify_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstModifyResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstModifyResponse),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstModifyResponse", &this_info, 0);
	}
	return this_type;
}

LassoDstModifyResponse*
lasso_dst_modify_response_new(LassoUtilityStatus *status)
{
	LassoDstModifyResponse *modify_response;

	g_return_val_if_fail(LASSO_IS_UTILITY_STATUS(status) == TRUE, NULL);

	modify_response = g_object_new(LASSO_TYPE_DST_MODIFY_RESPONSE, NULL);

	modify_response->Status = status;

	return modify_response;
}

