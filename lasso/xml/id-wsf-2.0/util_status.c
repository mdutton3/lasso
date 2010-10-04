/* $Id: util_status.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "util_status.h"
#include "./idwsf2_strings.h"
#include "../../utils.h"

/**
 * SECTION:util_status
 * @short_description: &lt;util:Status&gt;
 *
 * <figure><title>Schema fragment for util:Status</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="StatusType">
 *   <xs:annotation>
 *     <xs:documentation>
 *       A type that may be used for status codes.
 *     </xs:documentation>
 *   </xs:annotation>
 *   <xs:sequence>
 *     <xs:element ref="Status" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="code" type="xs:string" use="required"/>
 *   <xs:attribute name="ref" type="IDReferenceType" use="optional"/>
 *   <xs:attribute name="comment" type="xs:string" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, Status),
		"LassoIdWsf2UtilStatus", NULL, NULL },
	{ "code", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, code), NULL, NULL, NULL},
	{ "ref", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, ref), NULL, NULL, NULL},
	{ "comment", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2UtilStatus, comment), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2UtilStatusClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Status");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_UTIL_HREF, LASSO_IDWSF2_UTIL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_util_status_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2UtilStatusClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2UtilStatus),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2UtilStatus", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_util_status_new:
 *
 * Creates a new #LassoIdWsf2UtilStatus object.
 *
 * Return value: a newly created #LassoIdWsf2UtilStatus object
 **/
LassoIdWsf2UtilStatus*
lasso_idwsf2_util_status_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_UTIL_STATUS, NULL);
}


/**
 * lasso_idwsf2_util_status_new_with_code:
 * @code1: first level code
 * @code2: second level code
 *
 * Creates a new #LassoIdWsf2UtilStatus containing code1 and if code2 is not-NULL a nested
 * #LassoIdWsf2UtilStatus containing code2.
 *
 * Return value: a newly created #LassoIdWsf2UtilStatus object
 **/
LassoIdWsf2UtilStatus*
lasso_idwsf2_util_status_new_with_code(const gchar *code1, const gchar *code2)
{
	LassoIdWsf2UtilStatus *status1 = lasso_idwsf2_util_status_new();

	lasso_assign_string(status1->code, code1);
	if (code2 != NULL) {
		LassoIdWsf2UtilStatus *status2 = lasso_idwsf2_util_status_new();
		lasso_assign_string(status2->code, code2);
		lasso_list_add_gobject(status1->Status, status2);
	}

	return status1;
}
