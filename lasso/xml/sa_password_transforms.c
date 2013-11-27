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
#include "sa_password_transforms.h"
#include "idwsf_strings.h"

/**
 * SECTION:sa_password_transforms
 * @short_description: &lt;sa:PasswordTransforms&gt;
 *
 * <figure><title>Schema fragment for sa:PasswordTransforms</title>
 * <programlisting><![CDATA[
 *   <xs:element name="PasswordTransforms">
 *      <xs:annotation>
 *        <xs:documentation>
 *          Contains ordered list of sequential password transformations
 *        </xs:documentation>
 *      </xs:annotation>
 *      <xs:complexType>
 *        <xs:sequence>
 *          <xs:element name="Transform" maxOccurs="unbounded">
 *            <xs:complexType>
 *              <xs:sequence>
 *                <xs:element name="Parameter" minOccurs="0" maxOccurs="unbounded">
 *                <xs:complexType>
 *                  <xs:simpleContent>
 *                    <xs:extension base="xs:string">
 *                      <xs:attribute name="name" type="xs:string" use="required"/>
 *                    </xs:extension>
 *                  </xs:simpleContent>
 *                </xs:complexType>
 *                </xs:eledment>
 *              </xs:sequence>
 *              <xs:attribute name="name" type="xs:anyURI" use="required"/>
 *              <xs:attribute name="id" type="xs:ID"use="optional"/>
 *            </xs:complexType>
 *          </xs:element>
 *        </xs:sequence>
 *      </xs:complexType>
 *  </xs:element>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Transform", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoSaPasswordTransforms, Transform), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaPasswordTransformsClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "PasswordTransforms");
	lasso_node_class_set_ns(nclass, LASSO_SA_HREF, LASSO_SA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_sa_password_transforms_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaPasswordTransformsClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaPasswordTransforms),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaPasswordTransforms", &this_info, 0);
	}
	return this_type;
}

LassoSaPasswordTransforms*
lasso_sa_password_transforms_new()
{
	LassoSaPasswordTransforms *node;

	node = g_object_new(LASSO_TYPE_SA_PASSWORD_TRANSFORMS, NULL);

	return node;
}
