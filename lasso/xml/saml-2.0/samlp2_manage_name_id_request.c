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
#include "samlp2_manage_name_id_request.h"

/**
 * SECTION:samlp2_manage_name_id_request
 * @short_description: &lt;samlp2:ManageNameIDRequest&gt;
 *
 * <figure><title>Schema fragment for samlp2:ManageNameIDRequest</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="ManageNameIDRequestType">
 *   <complexContent>
 *     <extension base="samlp:RequestAbstractType">
 *       <sequence>
 *         <choice>
 *           <element ref="saml:NameID"/>
 *           <element ref="saml:EncryptedID"/>
 *         </choice>
 *         <choice>
 *           <element ref="samlp:NewID"/>
 *           <element ref="samlp:NewEncryptedID"/>
 *           <element ref="samlp:Terminate"/>
 *         </choice>
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
	{ "NameID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2ManageNameIDRequest, NameID), NULL, NULL, NULL},
	{ "EncryptedID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2ManageNameIDRequest, EncryptedID),
		"LassoSaml2EncryptedElement", NULL, NULL},
	{ "NewID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSamlp2ManageNameIDRequest, NewID), NULL, NULL, NULL},
	{ "NewEncryptedID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2ManageNameIDRequest, NewEncryptedID),
		"LassoSaml2EncryptedElement", NULL, NULL},
	{ "Terminate", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2ManageNameIDRequest, Terminate), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlp2ManageNameIDRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ManageNameIDRequest");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp2_manage_name_id_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2ManageNameIDRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2ManageNameIDRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_REQUEST_ABSTRACT,
				"LassoSamlp2ManageNameIDRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_manage_name_id_request_new:
 *
 * Creates a new #LassoSamlp2ManageNameIDRequest object.
 *
 * Return value: a newly created #LassoSamlp2ManageNameIDRequest object
 **/
LassoNode*
lasso_samlp2_manage_name_id_request_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST, NULL);
}
