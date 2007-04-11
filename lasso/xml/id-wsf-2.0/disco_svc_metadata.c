/* $Id: disco_service_metadata.c 2261 2005-01-27 23:41:05 $ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <lasso/xml/id-wsf-2.0/disco_svc_metadata.h>
#include <lasso/xml/id-wsf-2.0/disco_endpoint_context.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-v2.0.xsd):
 * 
 * <xs:element name="SvcMD" type="SvcMetadataType"/>
 * <xs:complexType name="SvcMetadataType">
 *    <xs:sequence>
 *       <xs:element ref="Abstract"                              />
 *       <xs:element ref="ProviderID"                            />
 *       <xs:element ref="ServiceContext"  maxOccurs="unbounded" />
 *    </xs:sequence>
 *    <xs:attribute name="svcMDID" type="xs:string" use="optional" />
 * </xs:complexType>
 * 
 * <xs:element name="Abstract" type="xs:string"/>
 * <xs:element name="ProviderID" type="xs:anyURI"/>
 * <xs:element name="SvcMDID" type="xs:string" />
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Abstract", SNIPPET_CONTENT,
	  G_STRUCT_OFFSET(LassoDiscoServiceMetadata, Abstract) },
	{ "ProviderID", SNIPPET_CONTENT,
	  G_STRUCT_OFFSET(LassoDiscoServiceMetadata, ProviderID) },
	{ "ServiceContext", SNIPPET_NODE,
	  G_STRUCT_OFFSET(LassoDiscoServiceMetadata, ServiceContext) },
	{ "svcMDID", SNIPPET_ATTRIBUTE,
	  G_STRUCT_OFFSET(LassoDiscoServiceMetadata, id) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoServiceMetadata *node)
{
	node->Abstract = NULL;
	node->ProviderID = NULL;
	node->ServiceContext = NULL;
	node->id = NULL;
}

static void
class_init(LassoDiscoServiceMetadataClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SvcMD");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF, LASSO_IDWSF2_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_service_metadata_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoServiceMetadataClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoServiceMetadata),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoServiceMetadata", &this_info, 0);
	}
	return this_type;
}

LassoDiscoServiceMetadata*
lasso_disco_service_metadata_new(gchar *service_type, gchar *abstract, gchar *provider_id)
{
	LassoDiscoServiceMetadata *metadata;
	LassoDiscoEndpointContext *endpoint_context;

	metadata = g_object_new(LASSO_TYPE_DISCO_SERVICE_METADATA, NULL);

	metadata->Abstract = g_strdup(abstract);
	metadata->ProviderID = g_strdup(provider_id);

	endpoint_context = g_object_ref(lasso_disco_endpoint_context_new(provider_id));
	metadata->ServiceContext =
		g_object_ref(lasso_disco_service_context_new(service_type, endpoint_context));

	return metadata;
}
