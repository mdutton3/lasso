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
#include "soap_binding_ext_service_instance_update.h"
#include "idwsf_strings.h"

/**
 * SECTION:soap_binding_ext_service_instance_update
 * @short_description: &lt;soapbinding:ServiceInstanceUpdateType&gt;
 *
 * <figure><title>Schema fragment for soapbinding:ServiceInstanceUpdateType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ServiceInstanceUpdateType">
 *   <xs:sequence>
 *       <xs:element name="SecurityMechID" type="xs:anyURI" minOccurs="0" maxOccurs="unbounded"/>
 *       <xs:element name="Credential" minOccurs="0" maxOccurs="unbounded">
 *          <xs:complexType>
 *             <xs:sequence>
 *                <xs:any namespace="##any" processContents="lax"/>
 *             </xs:sequence>
 *             <xs:attribute name="notOnOrAfter" type="xs:dateTime" use="optional"/>
 *          </xs:complexType>
 *       </xs:element>
 *       <xs:element name="Endpoint" type="xs:anyURI" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 *   <xs:attribute ref="S:mustUnderstand" use="optional"/>
 *   <xs:attribute ref="S:actor" use="optional"/>
 * </xs:complexType>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "SecurityMechID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSoapBindingExtServiceInstanceUpdate, SecurityMechID), NULL, NULL, NULL},
	{ "Credential", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSoapBindingExtServiceInstanceUpdate, Credential), NULL, NULL, NULL},
	{ "Endpoint", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSoapBindingExtServiceInstanceUpdate, Endpoint), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSoapBindingExtServiceInstanceUpdate, id), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingExtServiceInstanceUpdate, mustUnderstand), NULL, NULL, NULL},
	{ "actor", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingExtServiceInstanceUpdate, actor), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapBindingExtServiceInstanceUpdateClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ServiceInstanceUpdate");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_BINDING_EXT_HREF, LASSO_SOAP_BINDING_EXT_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_binding_ext_service_instance_update_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapBindingExtServiceInstanceUpdateClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapBindingExtServiceInstanceUpdate),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapBindingExtServiceInstanceUpdate", &this_info, 0);
	}
	return this_type;
}

LassoSoapBindingExtServiceInstanceUpdate*
lasso_soap_binding_ext_service_instance_update_new()
{
	LassoSoapBindingExtServiceInstanceUpdate *node;

	node = g_object_new(LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE, NULL);

	return node;
}
