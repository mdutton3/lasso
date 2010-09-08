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

#include "private.h"
#include "sa_credentials.h"
#include "./idwsf_strings.h"

/**
 * SECTION:sa_credentials
 * @short_description: &lt;sa:Credentials&gt;
 *
 * <figure><title>Schema fragment for sa:Credentials</title>
 * <programlisting><![CDATA[
 *
 *     <xs:element name="Credentials" minOccurs="0">
 *     <xs:complexType>
 *       <xs:sequence>
 *         <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *       </xs:sequence>
 *     </xs:complexType>
 *     </xs:element>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoSaCredentials, any), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaCredentialsClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Credentials");
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_sa_credentials_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaCredentialsClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaCredentials),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaCredentials", &this_info, 0);
	}
	return this_type;
}

LassoSaCredentials*
lasso_sa_credentials_new()
{
	LassoSaCredentials *node;

	node = g_object_new(LASSO_TYPE_SA_CREDENTIALS, NULL);

	return node;
}
