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
#include "soap_binding_ext_credential.h"
#include "idwsf_strings.h"

/**
 * SECTION:soap_binding_ext_credential
 * @short_description: &lt;soapbinding:Credential&gt;
 *
 * <figure><title>Schema fragment for soapbinding:Credential</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Credential" minOccurs="0" maxOccurs="unbounded">
 *   <xs:complexType>
 *      <xs:sequence>
 *         <xs:any namespace="##any" processContents="lax"/>
 *      </xs:sequence>
 *      <xs:attribute name="notOnOrAfter" type="xs:dateTime" use="optional"/>
 *   </xs:complexType>
 * </xs:element>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSoapBindingExtCredential, any), NULL, NULL, NULL},
	{ "notOnOrAfter", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingExtCredential, notOnOrAfter), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapBindingExtCredentialClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Credential");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_BINDING_EXT_HREF, LASSO_SOAP_BINDING_EXT_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_binding_ext_credential_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapBindingExtCredentialClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapBindingExtCredential),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapBindingExtCredential", &this_info, 0);
	}
	return this_type;
}

LassoSoapBindingExtCredential*
lasso_soap_binding_ext_credential_new(LassoNode *any)
{
	LassoSoapBindingExtCredential *node;

	g_return_val_if_fail(LASSO_IS_NODE(any) != FALSE, NULL);

	node = g_object_new(LASSO_TYPE_SOAP_BINDING_EXT_CREDENTIAL, NULL);

	node->any = g_list_append(node->any, any);

	return node;
}
