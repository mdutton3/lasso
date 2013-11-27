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
#include "samlp2_manage_name_id_response.h"

/**
 * SECTION:samlp2_manage_name_id_response
 * @short_description: &lt;samlp2:ManageNameIDResponse&gt;
 *
 * <figure><title>Schema fragment for samlp2:ManageNameIDResponse</title>
 * <programlisting><![CDATA[
 *
 * <element name="ManageNameIDResponse" type="samlp:StatusResponseType"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoSamlp2ManageNameIDResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ManageNameIDResponse");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp2_manage_name_id_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2ManageNameIDResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2ManageNameIDResponse),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_STATUS_RESPONSE,
				"LassoSamlp2ManageNameIDResponse", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_manage_name_id_response_new:
 *
 * Creates a new #LassoSamlp2ManageNameIDResponse object.
 *
 * Return value: a newly created #LassoSamlp2ManageNameIDResponse object
 **/
LassoNode*
lasso_samlp2_manage_name_id_response_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_RESPONSE, NULL);
}
