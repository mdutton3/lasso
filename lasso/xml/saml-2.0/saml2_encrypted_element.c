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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../private.h"
#include "saml2_encrypted_element.h"
#include "../xml.h"
#include "../../utils.h"
#include "../../errors.h"
#include "../xml_enc.h"
#include "../../registry.h"

/**
 * SECTION:saml2_encrypted_element
 * @short_description: &lt;saml2:EncryptedElement&gt;
 *
 * This element can contain an encrypted XML document fragment, use
 * lasso_saml2_encrypted_element_decrypt() to retrieve it.
 *
 * <figure><title>Schema fragment for saml2:EncryptedElement</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="EncryptedElementType">
 *   <sequence>
 *     <element ref="xenc:EncryptedData"/>
 *     <element ref="xenc:EncryptedKey" minOccurs="0" maxOccurs="unbounded"/>
 *   </sequence>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "EncryptedData", SNIPPET_XMLNODE,
		G_STRUCT_OFFSET(LassoSaml2EncryptedElement, EncryptedData), NULL, NULL, NULL},
	{ "EncryptedKey", SNIPPET_LIST_XMLNODES,
		G_STRUCT_OFFSET(LassoSaml2EncryptedElement, EncryptedKey), NULL, NULL, NULL},
	{ "NameID", SNIPPET_NODE | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSaml2EncryptedElement, original_data), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoSaml2EncryptedElementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);

	lasso_node_class_set_nodename(nclass, "EncryptedElement");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml2_encrypted_element_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2EncryptedElementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2EncryptedElement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaml2EncryptedElement", &this_info, 0);
		lasso_registry_default_add_direct_mapping(LASSO_SAML2_ASSERTION_HREF, "EncryptedID",
				LASSO_LASSO_HREF, "LassoSaml2EncryptedElement");
		lasso_registry_default_add_direct_mapping(LASSO_SAML2_ASSERTION_HREF,
				"EncryptedAttribute", LASSO_LASSO_HREF,
				"LassoSaml2EncryptedElement");
		lasso_registry_default_add_direct_mapping(LASSO_SAML2_ASSERTION_HREF,
				"EncryptedAssertion", LASSO_LASSO_HREF,
				"LassoSaml2EncryptedElement");
		lasso_registry_default_add_direct_mapping(LASSO_SAML2_PROTOCOL_HREF,
				"NewEncryptedID", LASSO_LASSO_HREF, "LassoSaml2EncryptedElement");
	}
	return this_type;
}

/**
 * lasso_saml2_encrypted_element_new:
 *
 * Creates a new #LassoSaml2EncryptedElement object.
 *
 * Return value: a newly created #LassoSaml2EncryptedElement object
 **/
LassoNode*
lasso_saml2_encrypted_element_new()
{
	return g_object_new(LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT, NULL);
}

/**
 * lasso_saml2_encrypted_element_decrypt:
 * @encrypted_element: the #LassoSaml2EncryptedElement to decrypt
 * @encryption_private_key: the #xmlSecKey to decrypt the node
 *
 *
 * Decrypt the content of a #LassoSaml2EncryptedElement using the given #xmlSecKey.
 * The #xmlNode resulting of decrypting it is converted into a #LassoNode object.
 *
 * Return value: 0 if successful, an error otherwise.
 */
int
lasso_saml2_encrypted_element_decrypt(LassoSaml2EncryptedElement* encrypted_element,
		xmlSecKey *encryption_private_key, LassoNode **decrypted_node)
{
	return lasso_node_decrypt_xmlnode(encrypted_element->EncryptedData, encrypted_element->EncryptedKey, encryption_private_key, decrypted_node);
}
