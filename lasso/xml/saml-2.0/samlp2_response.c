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

#include "samlp2_response.h"
#include "saml2_assertion.h"
#include "saml2_encrypted_element.h"

/*
 * Schema fragment (saml-schema-protocol-2.0.xsd):
 *
 * <complexType name="ResponseType">
 *   <complexContent>
 *     <extension base="samlp:StatusResponseType">
 *       <choice minOccurs="0" maxOccurs="unbounded">
 *         <element ref="saml:Assertion"/>
 *         <element ref="saml:EncryptedAssertion"/>
 *       </choice>
 *     </extension>
 *   </complexContent>
 * </complexType>
 */

extern LassoNode* lasso_assertion_encrypt(LassoSaml2Assertion *assertion);

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Assertion", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSamlp2Response, Assertion) },
	{ "EncryptedAssertion", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSamlp2Response, EncryptedAssertion) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


static gchar*
build_query(LassoNode *node)
{
	char *ret, *deflated_message;

	deflated_message = lasso_node_build_deflated_query(node);
	ret = g_strdup_printf("SAMLResponse=%s", deflated_message);
	/* XXX: must support RelayState (which profiles?) */
	g_free(deflated_message);
	return ret;
}


static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	gboolean rc;
	char *relay_state = NULL;
	rc = lasso_node_init_from_saml2_query_fields(node, query_fields, &relay_state);
	if (rc && relay_state != NULL) {
		/* XXX: support RelayState? */
	}
	return rc;
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoSamlp2Response *response = LASSO_SAMLP2_RESPONSE(node);
	GList *assertions, *assertions_copy;
	LassoNode *encrypted_element = NULL;
	xmlNode *result;


	/* Encrypt Assertions for messages but not for dumps */
	if (lasso_dump == FALSE) {
		assertions_copy = g_list_copy(response->Assertion);
		for (assertions = response->Assertion;
				assertions != NULL; assertions = g_list_next(assertions)) {
			encrypted_element = lasso_assertion_encrypt(assertions->data);
			if (encrypted_element != NULL) {
				/* use EncryptedAssertion */
				response->EncryptedAssertion = g_list_append(
					response->EncryptedAssertion, encrypted_element);
				/* and remove original unencrypted from Assertion */
				response->Assertion = g_list_remove(response->Assertion,
					assertions->data);
			}
		}
	}

	result = parent_class->get_xmlNode(node, lasso_dump);

	if (lasso_dump == FALSE) {
		g_list_free(response->Assertion);
		response->Assertion = assertions_copy;
		for (assertions = response->EncryptedAssertion; assertions != NULL;
				assertions = g_list_next(assertions)) {
			lasso_node_destroy(assertions->data);
		}
		response->EncryptedAssertion = NULL;
	}

	return result;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlp2Response *node)
{
	node->Assertion = NULL;
	node->EncryptedAssertion = NULL;
}

static void
class_init(LassoSamlp2ResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Response"); 
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp2_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2ResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2Response),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_STATUS_RESPONSE,
				"LassoSamlp2Response", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_response_new:
 *
 * Creates a new #LassoSamlp2Response object.
 *
 * Return value: a newly created #LassoSamlp2Response object
 **/
LassoNode*
lasso_samlp2_response_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_RESPONSE, NULL);
}
