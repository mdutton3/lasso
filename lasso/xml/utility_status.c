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
#include "utility_status.h"

/**
 * SECTION:utility_status
 * @short_description: &lt;utility:Status&gt;
 *
 * <figure><title>Schema fragment for utility:Status</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Status" type="StatusType">
 *   <xs:annotation>
 *     <xs:documentation> A standard Status type</xs:documentation>
 *   </xs:annotation>
 * </xs:element>
 * <xs:complexType name="StatusType">
 *   <xs:annotation>
 *     <xs:documentation> A type that may be used for status codes. </xs:documentation>
 *   </xs:annotation>
 *   <xs:sequence>
 *     <xs:element ref="Status" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="code" type="xs:QName" use="required"/>
 *   <xs:attribute name="ref" type="xs:NCName" use="optional"/>
 *   <xs:attribute name="comment" type="xs:string" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoUtilityStatus, Status), NULL, NULL, NULL},
	{ "code", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoUtilityStatus, code), NULL, NULL, NULL},
	{ "ref", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoUtilityStatus, ref), NULL, NULL, NULL},
	{ "comment", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoUtilityStatus, comment), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoUtilityStatusClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Status");
	/* no namespace */
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_utility_status_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoUtilityStatusClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoUtilityStatus),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoUtilityStatus", &this_info, 0);
	}
	return this_type;
}

LassoUtilityStatus*
lasso_utility_status_new(const char *code)
{
	LassoUtilityStatus *status;

	g_return_val_if_fail(code != NULL, NULL);

	status = g_object_new(LASSO_TYPE_UTILITY_STATUS, NULL);

	status->code = g_strdup(code);

	return status;
}

