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
#include "disco_resource_offering.h"
#include "idwsf_strings.h"
#include "../utils.h"

/**
 * SECTION:disco_resource_offering
 * @short_description: &lt;disco:ResourceOffering&gt;
 *
 * <figure><title>Schema fragment for disco:ResourceOffering</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="ResourceOffering" type="ResourceOfferingType"/>
 * <xs:complexType name="ResourceOfferingType">
 *   <xs:sequence>
 *     <xs:group ref="ResourceIDGroup"/>
 *     <xs:element name="ServiceInstance" type="ServiceInstanceType"/>
 *     <xs:element ref="Options" minOccurs="0"/>
 *     <xs:element name="Abstract" type="xs:string" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="entryID" type="IDType" use="optional"/>
 * </xs:complexType>
 *
 * Schema fragment (liberty-idwsf-utility-1.0-errata-v1.0.xsd)
 *
 * <xs:simpleType name="IDType">
 *   <xs:restriction base="xs:string"/>
 * </xs:simpleType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoResourceOffering, ResourceID), NULL, NULL, NULL},
	{ "EncryptedResourceID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoResourceOffering, EncryptedResourceID), NULL, NULL, NULL},
	{ "ServiceInstance", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoResourceOffering, ServiceInstance), NULL, NULL, NULL},
	{ "Options", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoResourceOffering, Options), NULL, NULL, NULL},
	{ "Abstract", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoDiscoResourceOffering, Abstract), NULL, NULL, NULL},
	{ "entryID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoDiscoResourceOffering, entryID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoResourceOfferingClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ResourceOffering");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_resource_offering_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoResourceOfferingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoResourceOffering),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoResourceOffering", &this_info, 0);
	}
	return this_type;
}

LassoDiscoResourceOffering*
lasso_disco_resource_offering_new(LassoDiscoServiceInstance *serviceInstance)
{
	LassoDiscoResourceOffering *resource;

	g_return_val_if_fail(LASSO_IS_DISCO_SERVICE_INSTANCE(serviceInstance), NULL);

	resource = g_object_new(LASSO_TYPE_DISCO_RESOURCE_OFFERING, NULL);
	lasso_assign_gobject(resource->ServiceInstance, serviceInstance);

	return resource;
}
