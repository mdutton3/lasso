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
#include "soap_body.h"

/**
 * SECTION:soap_body
 * @short_description: &lt;soap:Body&gt;
 *
 * <figure><title>Schema fragment for soap:Body</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Body" type="tns:Body"/>
 *   <xs:complexType name="Body">
 *   <xs:sequence>
 *     <xs:any namespace="##any" minOccurs="0" maxOccurs="unbounded" processContents="lax"/>
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##any" processContents="lax">
 *	<xs:annotation>
 *	<xs:documentation>
 *	    Prose in the spec does not specify that attributes are allowed on the Body element
 *	</xs:documentation>
 *      </xs:annotation>
 *   </xs:anyAttribute>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "any", SNIPPET_LIST_NODES | SNIPPET_ANY, G_STRUCT_OFFSET(LassoSoapBody, any), NULL, NULL,
		NULL},
	{ "Id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSoapBody, Id), NULL, LASSO_WSUTIL1_PREFIX,
		LASSO_WSUTIL1_HREF },
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
class_init(LassoSoapBodyClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(nclass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Body");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_body_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapBodyClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapBody),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapBody", &this_info, 0);
	}
	return this_type;
}

LassoSoapBody*
lasso_soap_body_new()
{
	LassoSoapBody *node;

	node = g_object_new(LASSO_TYPE_SOAP_BODY, NULL);

	return node;
}

LassoSoapBody*
lasso_soap_body_new_from_message(const gchar *message)
{
	LassoSoapBody *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_SOAP_BODY, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}
