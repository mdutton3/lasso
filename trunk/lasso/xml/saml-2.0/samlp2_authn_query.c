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
#include "samlp2_authn_query.h"

/**
 * SECTION:samlp2_authn_query
 * @short_description: &lt;samlp2:AuthnQuery&gt;
 *
 * <figure><title>Schema fragment for samlp2:AuthnQuery</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="AuthnQueryType">
 *   <complexContent>
 *     <extension base="samlp:SubjectQueryAbstractType">
 *       <sequence>
 *         <element ref="samlp:RequestedAuthnContext" minOccurs="0"/>
 *       </sequence>
 *       <attribute name="SessionIndex" type="string" use="optional"/>
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
	{ "RequestedAuthnContext", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnQuery, RequestedAuthnContext), NULL, NULL, NULL},
	{ "SessionIndex", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnQuery, SessionIndex), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlp2AuthnQueryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnQuery");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp2_authn_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2AuthnQueryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2AuthnQuery),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_SUBJECT_QUERY_ABSTRACT,
				"LassoSamlp2AuthnQuery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_authn_query_new:
 *
 * Creates a new #LassoSamlp2AuthnQuery object.
 *
 * Return value: a newly created #LassoSamlp2AuthnQuery object
 **/
LassoNode*
lasso_samlp2_authn_query_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_AUTHN_QUERY, NULL);
}
