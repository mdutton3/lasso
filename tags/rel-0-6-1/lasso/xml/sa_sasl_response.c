/* $Id$ 
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

#include <lasso/xml/sa_sasl_response.h>

/*
 * Schema fragments (lib-arch-authn-svc.xsd):
 * 
 * <xs:element name="SASLResponse">
 * <xs:complexType>
 *   <xs:sequence>
 *     <xs:element ref="Status"/>
 *     <xs:element ref="PasswordTransforms" minOccurs="0"/>
 *     <xs:element name="Data" minOccurs="0">
 *     <xs:complexType>
 *       <xs:simpleContent>
 *         <xs:extension base="xs:base64Binary"/>
 *       </xs:simpleContent>
 *     </xs:complexType>
 *     </xs:element>
 *     <xs:element ref="disco:ResourceOffering" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="Credentials" minOccurs="0">
 *     <xs:complexType>
 *       <xs:sequence>
 *         <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *       </xs:sequence>
 *     </xs:complexType>
 *     </xs:element>
 *   </xs:sequence> 
 *   <xs:attribute name="serverMechanism" type="xs:string" ="optional"/>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 * </xs:element>
 *
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSaSaslResponse, Status) },
	{ "PasswordTransforms", SNIPPET_LIST_NODES,
	  G_STRUCT_OFFSET(LassoSaSaslResponse, PasswordTransforms) },
	{ "Data", SNIPPET_LIST_CONTENT,
	  G_STRUCT_OFFSET(LassoSaSaslResponse, Data) },
	{ "ResourceOffering", SNIPPET_LIST_NODES,
	  G_STRUCT_OFFSET(LassoSaSaslResponse, ResourceOffering) },
	/* TODO : Credentials */
	{ "serverMechanism", SNIPPET_ATTRIBUTE,
	  G_STRUCT_OFFSET(LassoSaSaslResponse, serverMechanism) },
	{ "id", SNIPPET_ATTRIBUTE,
	  G_STRUCT_OFFSET(LassoSaSaslResponse, id) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSaSaslResponse *node)
{
	node->Status = NULL;
	node->PasswordTransforms = NULL;
	node->Data = NULL;
	node->ResourceOffering = NULL;
	node->Credentials = NULL;
	node->any = NULL;
	node->serverMechanism = NULL;
	node->id = NULL;
}

static void
class_init(LassoSaSaslResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SASLResponse");
	lasso_node_class_set_ns(nclass, LASSO_SA_HREF, LASSO_SA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_sa_sasl_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaSaslResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaSaslResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaSaslResponse", &this_info, 0);
	}
	return this_type;
}

LassoSaSaslResponse*
lasso_sa_sasl_response_new(LassoUtilityStatus *status)
{
	LassoSaSaslResponse *node;

	node = g_object_new(LASSO_TYPE_SA_SASL_RESPONSE, NULL);

	node->Status = status;

	return node;
}

LassoSaSaslResponse*
lasso_sa_sasl_response_new_from_message(const gchar *message)
{
	LassoSaSaslResponse *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_SA_SASL_RESPONSE, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}
