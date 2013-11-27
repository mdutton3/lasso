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

#include "soap_detail.h"
#include "../private.h"

/*
 *
 * <xs: element name="Fault" type="tns: Fault"/>
 * <xs: complexType name="Fault" final="extension">
 *   <xs: annotation>
 *     <xs: documentation>
 *       Fault reporting structure
 *     </xs: documentation>
 *   </xs: annotation>
 *   <xs: sequence>
 *     <xs: element name="faultcode" type="xs: QName"/>
 *     <xs: element name="faultstring" type="xs: string"/>
 *     <xs: element name="faultactor" type="xs: anyURI" minOccurs="0"/>
 *     <xs: element name="detail" type="tns: detail" minOccurs="0"/>
 *   </xs: sequence>
 *  </xs: complexType>
 *
 *  <xs: complexType name="detail">
 *    <xs: sequence>
 *      <xs: any namespace="##any" minOccurs="0" maxOccurs="unbounded" processContents="lax"/>
 *    </xs: sequence>
 *    <xs: anyAttribute namespace="##any" processContents="lax"/>
 *  </xs: complexType>
 *
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoSoapDetail, any), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapDetailClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "detail");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_detail_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapDetailClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapDetail),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapDetail", &this_info, 0);
	}
	return this_type;
}

LassoSoapDetail*
lasso_soap_detail_new()
{
	LassoSoapDetail *node;

	node = g_object_new(LASSO_TYPE_SOAP_DETAIL, NULL);

	return node;
}

LassoSoapDetail*
lasso_soap_detail_new_from_message(const gchar *message)
{
	LassoSoapDetail *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_SOAP_DETAIL, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}
