/* $Id: disco_svc_md_register.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "disco_svc_md_register.h"
#include "./idwsf2_strings.h"
#include "disco_svc_metadata.h"

/**
 * SECTION:disco_svc_md_register
 * @short_description: &lt;disco:SvcMDRegister&gt;
 *
 * <figure><title>Schema fragment for disco:SvcMDRegister</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="SvcMDRegisterType">
 *   <xs:sequence>
 *     <xs:element ref="SvcMD" maxOccurs="unbounded" />
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "SvcMD", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDRegister, SvcMD),
		"LassoIdWsf2DiscoSvcMetadata", NULL, NULL },
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDRegister, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DiscoSvcMDRegister *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2DiscoSvcMDRegisterClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SvcMDRegister");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCOVERY_HREF, LASSO_IDWSF2_DISCOVERY_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_svc_md_register_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoSvcMDRegisterClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoSvcMDRegister),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoSvcMDRegister", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_svc_md_register_new:
 *
 * Creates a new #LassoIdWsf2DiscoSvcMDRegister object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoSvcMDRegister object
 **/
LassoIdWsf2DiscoSvcMDRegister*
lasso_idwsf2_disco_svc_md_register_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER, NULL);
}


/**
 * lasso_idwsf2_disco_svc_md_register_new_full:
 * @service_type: the service type for the registered metadatas
 * @abstract: the human description for the service
 * @provider_id: the SAML provider id of the service
 * @soap_endpoint: the SOAP endpoint URL for the service
 *
 * Create and initialize a complete message for registering new metadatas at a discovery service.
 *
 * Return value: a new filled and initialized #LassoIdWsf2DiscoSvcMDRegister if successfull, NULL
 * otherwise.
 */
LassoIdWsf2DiscoSvcMDRegister*
lasso_idwsf2_disco_svc_md_register_new_full(const gchar *service_type, const gchar *abstract,
		const gchar *provider_id, const gchar *soap_endpoint)
{
	LassoIdWsf2DiscoSvcMDRegister *metadata_register;
	LassoIdWsf2DiscoSvcMetadata *metadata;

	metadata_register = lasso_idwsf2_disco_svc_md_register_new();
	metadata = lasso_idwsf2_disco_svc_metadata_new_full(service_type, abstract, provider_id,
			soap_endpoint);
	metadata_register->SvcMD = g_list_append(
			metadata_register->SvcMD, metadata);

	return metadata_register;
}
