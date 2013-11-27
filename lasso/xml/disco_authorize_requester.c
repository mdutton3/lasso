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

#include "private.h"
#include "disco_authorize_requester.h"
#include "idwsf_strings.h"

/**
 * SECTION:disco_authorize_requester
 * @short_description: &lt;disco:DirectiveType&gt;
 *
 * <figure><title>Schema fragment for disco:DirectiveType</title>
 * <programlisting><![CDATA[
 *
 * <xs: complexType name="DirectiveType">
 *  <xs: attribute name="descriptionIDRefs" type="xs:IDREFS" use="optional"/>
 * </xs: complexType>
 * <xs: element name="AuthorizeRequester" type="DirectiveType"/>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "descriptionIDRefs",SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoDiscoAuthorizeRequester, descriptionIDRefs), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoAuthorizeRequesterClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthorizeRequester");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_authorize_requester_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoAuthorizeRequesterClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoAuthorizeRequester),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoAuthorizeRequester", &this_info, 0);
	}
	return this_type;
}

LassoDiscoAuthorizeRequester*
lasso_disco_authorize_requester_new()
{
	LassoDiscoAuthorizeRequester *node;

	node = g_object_new(LASSO_TYPE_DISCO_AUTHORIZE_REQUESTER, NULL);

	return node;
}
