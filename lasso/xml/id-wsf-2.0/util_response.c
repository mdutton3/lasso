/* $Id: util_response.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "util_response.h"
#include "./idwsf2_strings.h"
#include "../../utils.h"

/**
 * SECTION:util_response
 * @short_description: &lt;util:Response&gt;
 *
 * <figure><title>Schema fragment for util:Response</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ResponseType">
 *   <xs:sequence>
 *     <xs:element ref="Status"       minOccurs="1" maxOccurs="1"/>
 *     <xs:element ref="Extension"    minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute ref="itemIDRef" use="optional"/>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2UtilResponse, Status),
		"LassoIdWsf2UtilStatus", NULL, NULL },
	{ "Extension", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2UtilResponse, Extension),
		"LassoIdWsf2Utilextension", NULL, NULL },
	{ "itemIDRef", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2UtilResponse, itemIDRef), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2UtilResponse, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2UtilResponse *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2UtilResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Response");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_UTIL_HREF, LASSO_IDWSF2_UTIL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_util_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2UtilResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2UtilResponse),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2UtilResponse", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_util_response_new:
 *
 * Creates a new #LassoIdWsf2UtilResponse object.
 *
 * Return value: a newly created #LassoIdWsf2UtilResponse object
 **/
LassoIdWsf2UtilResponse*
lasso_idwsf2_util_response_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_UTIL_RESPONSE, NULL);
}

/**
 * lasso_idwsf2_util_response_set_status:
 * @idwsf2_util_response: a #LassoIdWsf2UtilResponse object
 * @status: a status code identifier
 *
 * Set the first level status code and no second level status code.
 */
void
lasso_idwsf2_util_response_set_status(LassoIdWsf2UtilResponse *idwsf2_util_response,
		const char *status)
{
	LassoIdWsf2UtilStatus *idwsf2_util_status;

	if (! LASSO_IS_IDWSF2_UTIL_RESPONSE(idwsf2_util_response))
		return;
	if (status == NULL || status[0] == '\0')
		return;

	idwsf2_util_status = lasso_idwsf2_util_status_new();
	lasso_assign_string(idwsf2_util_status->code, status);
	lasso_assign_new_gobject(idwsf2_util_response->Status, idwsf2_util_status);
}

void
lasso_idwsf2_util_response_set_status2(LassoIdWsf2UtilResponse *idwsf2_util_response,
		const char *status, const char *status2)
{
	LassoIdWsf2UtilStatus *idwsf2_util_status = NULL;
	LassoIdWsf2UtilStatus *idwsf2_util_status2 = NULL;

	if (! LASSO_IS_IDWSF2_UTIL_RESPONSE(idwsf2_util_response))
		return;
	if (status2 == NULL || status2[0] == '\0')
		return;

	if (status) {
		idwsf2_util_status = lasso_idwsf2_util_status_new();
		lasso_assign_string(idwsf2_util_status->code, status);
	} else {
		if (LASSO_IS_IDWSF2_UTIL_STATUS(idwsf2_util_response->Status)) {
			idwsf2_util_status = idwsf2_util_response->Status;
		} else {
			return;
		}
	}

	if (idwsf2_util_status) {
		idwsf2_util_status2 = lasso_idwsf2_util_status_new();
		lasso_assign_string(idwsf2_util_status2->code, status2);
		lasso_list_add_new_gobject(idwsf2_util_status->Status, idwsf2_util_status2);
		lasso_assign_new_gobject(idwsf2_util_response->Status, idwsf2_util_status);
	}
}
