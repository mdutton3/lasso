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
#include "saml2_base_idabstract.h"

/**
 * SECTION:saml2_base_idabstract
 * @short_description: &lt;saml2:BaseIDAbstract&gt;
 *
 * <figure><title>Schema fragment for saml2:BaseIDAbstract</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="BaseIDAbstractType" abstract="true">
 *   <attributeGroup ref="saml:IDNameQualifiers"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "NameQualifier", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSaml2BaseIDAbstract, NameQualifier), NULL, NULL, NULL},
	{ "SPNameQualifier", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSaml2BaseIDAbstract, SPNameQualifier), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaml2BaseIDAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "BaseIDAbstract");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml2_base_idabstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2BaseIDAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2BaseIDAbstract),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaml2BaseIDAbstract", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml2_base_idabstract_new:
 *
 * Creates a new #LassoSaml2BaseIDAbstract object.
 *
 * Return value: a newly created #LassoSaml2BaseIDAbstract object
 **/
LassoNode*
lasso_saml2_base_idabstract_new()
{
	return g_object_new(LASSO_TYPE_SAML2_BASE_IDABSTRACT, NULL);
}
