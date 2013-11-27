/* $Id: subsref_delete_response.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "subsref_delete_response.h"
#include "idwsf2_strings.h"

/**
 * SECTION:subsref_delete_response
 * @short_description: &lt;subsref:DeleteResponse&gt;
 *
 * <figure><title>Schema fragment for subsref:DeleteResponse</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="DeleteResponseType">
 *   <xs:complexContent>
 *     <xs:extension base="lu:ResponseType"/>
 *   </xs:complexContent>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoIdWsf2SubsRefDeleteResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "DeleteResponse");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SUBSREF_HREF, LASSO_IDWSF2_SUBSREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_subsref_delete_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SubsRefDeleteResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SubsRefDeleteResponse),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_UTIL_RESPONSE,
				"LassoIdWsf2SubsRefDeleteResponse", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_subsref_delete_response_new:
 *
 * Creates a new #LassoIdWsf2SubsRefDeleteResponse object.
 *
 * Return value: a newly created #LassoIdWsf2SubsRefDeleteResponse object
 **/
LassoIdWsf2SubsRefDeleteResponse*
lasso_idwsf2_subsref_delete_response_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SUBSREF_DELETE_RESPONSE, NULL);
}
