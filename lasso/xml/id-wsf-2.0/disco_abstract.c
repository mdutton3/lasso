/* $Id: disco_abstract.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "disco_abstract.h"
#include "idwsf2_strings.h"

/**
 * SECTION:disco_abstract
 * @short_description: &lt;disco:Abstract&gt;
 *
 * <figure><title>Schema fragment for disco:Abstract</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Abstract" type="xs:string"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "content", SNIPPET_TEXT_CHILD,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoAbstract, content), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DiscoAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Abstract");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCOVERY_HREF, LASSO_IDWSF2_DISCOVERY_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_abstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoAbstract),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoAbstract", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_abstract_new:
 *
 * Creates a new #LassoIdWsf2DiscoAbstract object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoAbstract object
 **/
LassoIdWsf2DiscoAbstract*
lasso_idwsf2_disco_abstract_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_ABSTRACT, NULL);
}


/**
 * lasso_idwsf2_disco_abstract_new_with_string:
 * @content: the content string
 *
 * Creates a new #LassoIdWsf2DiscoAbstract object and initializes it
 * with @content as content.
 *
 * Return value: a newly created #LassoIdWsf2DiscoAbstract object
 **/
LassoIdWsf2DiscoAbstract*
lasso_idwsf2_disco_abstract_new_with_string(const char *content)
{
	LassoIdWsf2DiscoAbstract *object;
	object = g_object_new(LASSO_TYPE_IDWSF2_DISCO_ABSTRACT, NULL);
	object->content = g_strdup(content);
	return object;
}
