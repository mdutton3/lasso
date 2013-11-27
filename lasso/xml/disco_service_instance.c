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
#include "disco_service_instance.h"
#include "idwsf_strings.h"

/**
 * SECTION:disco_service_instance
 * @short_description: &lt;disco:ServiceInstanceType&gt;
 *
 * <figure><title>Schema fragment for disco:ServiceInstanceType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ServiceInstanceType">
 *   <xs:sequence>
 *     <xs:element ref="ServiceType"/>
 *     <xs:element name="ProviderID" type="md:entityIDType"/>
 *     <xs:element name="Description" type="DescriptionType" minOccurs="1" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 *
 * <xs:element name="ServiceType" type="xs:anyURI"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ServiceType", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoDiscoServiceInstance, ServiceType), NULL, NULL, NULL},
	{ "ProviderID",  SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoDiscoServiceInstance, ProviderID), NULL, NULL, NULL},
	{ "Description", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoDiscoServiceInstance, Description), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoServiceInstanceClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ServiceInstance");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_service_instance_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoServiceInstanceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoServiceInstance),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoServiceInstance", &this_info, 0);
	}
	return this_type;
}

LassoDiscoServiceInstance*
lasso_disco_service_instance_new(const gchar *serviceType,
		const gchar *providerID,
		LassoDiscoDescription *description)
{
	LassoDiscoServiceInstance *service_instance;

	g_return_val_if_fail (serviceType != NULL, NULL);
	g_return_val_if_fail (providerID != NULL, NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description) == TRUE, NULL);

	g_object_ref(description);

	service_instance = g_object_new(LASSO_TYPE_DISCO_SERVICE_INSTANCE, NULL);

	service_instance->ServiceType = g_strdup(serviceType);
	service_instance->ProviderID = g_strdup(providerID);

	service_instance->Description = g_list_append(service_instance->Description,
			description);

	return service_instance;
}

LassoDiscoServiceInstance*
lasso_disco_service_instance_copy(LassoDiscoServiceInstance *serviceInstance)
{
	LassoDiscoServiceInstance *newServiceInstance;
	LassoDiscoDescription *newDescription;
	GList *description;

	g_return_val_if_fail(LASSO_IS_DISCO_SERVICE_INSTANCE(serviceInstance) == TRUE, NULL);

	newServiceInstance = g_object_new(LASSO_TYPE_DISCO_SERVICE_INSTANCE, NULL);

	newServiceInstance->ServiceType = g_strdup(serviceInstance->ServiceType);
	newServiceInstance->ProviderID = g_strdup(serviceInstance->ProviderID);

	description = serviceInstance->Description;
	while (description) {
		newDescription = lasso_disco_description_copy(
			LASSO_DISCO_DESCRIPTION(description->data));
		newServiceInstance->Description = g_list_append(newServiceInstance->Description,
								newDescription);
		description = description->next;
	}

	return newServiceInstance;
}
