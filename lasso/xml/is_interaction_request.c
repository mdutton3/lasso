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

#include <lasso/xml/is_interaction_request.h>

/*
 * Schema fragments (liberty-idwsf-interaction-svc-v1.0.xsd):
 *
 * <xs:element name="InteractionRequest" type="InteractionRequestType"/>
 * <xs:complexType name="InteractionRequestType">
 *   <xs:sequence>
 *     <xs:group ref="ResourceIDGroup" minOccurs="0"/>
 *     <xs:element ref="Inquiry" maxOccurs="unbounded"/>
 *     <xs:element ref="ds:KeyInfo" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 *   <xs:attribute name="language" type="xs:NMTOKENS" use="optional"/>
 *   <xs:attribute name="maxInteractTime" type="xs:integer" use="optional"/>
 *   <xs:attribute name="signed" type="xs:token" use="optional"/>
 * </xs:complexType>
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoIsInteractionRequest, ResourceID) },
	{ "EncryptedResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoIsInteractionRequest,
							       EncryptedResourceID) },
	{ "Inquiry", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoIsInteractionRequest, Inquiry) },
	/* TODO : KeyInfo */
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsInteractionRequest, id) },
	{ "language", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsInteractionRequest, language) },
	{ "maxInteractTime", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsInteractionRequest,
								maxInteractTime) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIsInteractionRequest *node)
{
	node->ResourceID = NULL;
	node->EncryptedResourceID = NULL;
	node->Inquiry = NULL;
	/* TODO : KeyInfo */
	node->id = NULL;
	node->language = NULL;
	node->maxInteractTime = 0; /* FIXME : optional integer attribute */
	/* TODO : signed */
}

static void
class_init(LassoIsInteractionRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "InteractionRequest");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_interaction_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsInteractionRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsInteractionRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsInteractionRequest", &this_info, 0);
	}
	return this_type;
}

LassoIsInteractionRequest*
lasso_is_interaction_request_new()
{
	LassoIsInteractionRequest *node;

	node = g_object_new(LASSO_TYPE_IS_INTERACTION_REQUEST, NULL);

	return node;
}

LassoIsInteractionRequest*
lasso_is_interaction_request_new_from_message(const char *msg)
{
	LassoIsInteractionRequest *node;

	node = g_object_new(LASSO_TYPE_IS_INTERACTION_REQUEST, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), msg);

	return node;
}
