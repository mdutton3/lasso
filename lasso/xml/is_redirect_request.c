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
#include "is_redirect_request.h"
#include "idwsf_strings.h"

/**
 * SECTION:is_redirect_request
 * @short_description: &lt;is:RedirectRequest&gt;
 *
 * <figure><title>Schema fragment for is:RedirectRequest</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="RedirectRequest" type="RedirectRequestType"/>
 * <xs:complexType name="RedirectRequestType">
 *    <xs:attribute name="redirectURL" type="xs:anyURI" use="required"/>
 * </xs:complexType>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "redirectURL", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsRedirectRequest, redirectURL), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIsRedirectRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RedirectRequest");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_redirect_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsRedirectRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsRedirectRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsRedirectRequest", &this_info, 0);
	}
	return this_type;
}

LassoIsRedirectRequest*
lasso_is_redirect_request_new(const char *redirectURL)
{
	LassoIsRedirectRequest *node;

	node = g_object_new(LASSO_TYPE_IS_REDIRECT_REQUEST, NULL);

	node->redirectURL = g_strdup(redirectURL);

	return node;
}
