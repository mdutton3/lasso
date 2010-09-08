/* $Id: disco_svc_metadata.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../private.h"
#include "disco_svc_metadata.h"
#include "./idwsf2_strings.h"
#include "disco_endpoint_context.h"
#include "disco_service_context.h"

/**
 * SECTION:disco_svc_metadata
 * @short_description: &lt;disco:SvcMetadata&gt;
 *
 * <figure><title>Schema fragment for disco:SvcMetadata</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="SvcMetadataType">
 *   <xs:sequence>
 *     <xs:element ref="Abstract"                              />
 *     <xs:element ref="ProviderID"                            />
 *     <xs:element ref="ServiceContext"  maxOccurs="unbounded" />
 *   </xs:sequence>
 *   <xs:attribute name="svcMDID" type="xs:string" use="optional" />
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Abstract", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMetadata, Abstract), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMetadata, ProviderID), NULL, NULL, NULL},
	{ "ServiceContext", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMetadata, ServiceContext),
		"LassoIdWsf2DiscoServiceContext", NULL, NULL },
	{ "svcMDID", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMetadata, svcMDID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DiscoSvcMetadataClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SvcMD");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCOVERY_HREF, LASSO_IDWSF2_DISCOVERY_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_svc_metadata_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoSvcMetadataClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoSvcMetadata),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoSvcMetadata", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_svc_metadata_new:
 *
 * Creates a new #LassoIdWsf2DiscoSvcMetadata object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoSvcMetadata object
 **/
LassoIdWsf2DiscoSvcMetadata*
lasso_idwsf2_disco_svc_metadata_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_SVC_METADATA, NULL);
}


LassoIdWsf2DiscoSvcMetadata*
lasso_idwsf2_disco_svc_metadata_new_full(const gchar *service_type, const gchar *abstract,
		const gchar *provider_id, const gchar *soap_endpoint)
{
	LassoIdWsf2DiscoSvcMetadata *metadata;
	LassoIdWsf2DiscoEndpointContext *endpoint_context;

	metadata = g_object_new(LASSO_TYPE_IDWSF2_DISCO_SVC_METADATA, NULL);

	metadata->Abstract = g_strdup(abstract);
	metadata->ProviderID = g_strdup(provider_id);

	endpoint_context = lasso_idwsf2_disco_endpoint_context_new_full(soap_endpoint);
	metadata->ServiceContext = g_list_append(NULL,
		lasso_idwsf2_disco_service_context_new_full(service_type, endpoint_context));
	g_object_unref(endpoint_context);

	return metadata;
}

