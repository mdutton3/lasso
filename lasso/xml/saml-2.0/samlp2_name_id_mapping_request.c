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

#include "../private.h"
#include "samlp2_name_id_mapping_request.h"

/**
 * SECTION:samlp2_name_id_mapping_request
 * @short_description: &lt;samlp2:NameIDMappingRequest&gt;
 *
 * <figure><title>Schema fragment for samlp2:NameIDMappingRequest</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="NameIDMappingRequestType">
 *   <complexContent>
 *     <extension base="samlp:RequestAbstractType">
 *       <sequence>
 *         <choice>
 *           <element ref="saml:BaseID"/>
 *           <element ref="saml:NameID"/>
 *           <element ref="saml:EncryptedID"/>
 *         </choice>
 *         <element ref="samlp:NameIDPolicy"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "BaseID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlp2NameIDMappingRequest, BaseID), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "NameID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlp2NameIDMappingRequest, NameID), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "EncryptedID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlp2NameIDMappingRequest,
			EncryptedID), NULL, LASSO_SAML2_ASSERTION_PREFIX,
	LASSO_SAML2_ASSERTION_HREF},
	{ "NameIDPolicy", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2NameIDMappingRequest, NameIDPolicy), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlp2NameIDMappingRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "NameIDMappingRequest");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp2_name_id_mapping_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2NameIDMappingRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2NameIDMappingRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_REQUEST_ABSTRACT,
				"LassoSamlp2NameIDMappingRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_name_id_mapping_request_new:
 *
 * Creates a new #LassoSamlp2NameIDMappingRequest object.
 *
 * Return value: a newly created #LassoSamlp2NameIDMappingRequest object
 **/
LassoNode*
lasso_samlp2_name_id_mapping_request_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST, NULL);
}
