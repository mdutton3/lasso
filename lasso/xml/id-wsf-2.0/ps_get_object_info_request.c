/* $Id: ps_get_object_info_request.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "ps_get_object_info_request.h"
#include "idwsf2_strings.h"

/**
 * SECTION:ps_get_object_info_request
 * @short_description: &lt;ps:GetObjectInfoRequest&gt;
 *
 * <figure><title>Schema fragment for ps:GetObjectInfoRequest</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="GetObjectInfoRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="TargetObjectID" minOccurs="0"/>
 *         <xs:element ref="Subscription" minOccurs="0"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "TargetObjectID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2PsGetObjectInfoRequest, TargetObjectID), NULL, NULL, NULL},
	{ "Subscription", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2PsGetObjectInfoRequest, Subscription), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2PsGetObjectInfoRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "GetObjectInfoRequest");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_PS_HREF, LASSO_IDWSF2_PS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_ps_get_object_info_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2PsGetObjectInfoRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2PsGetObjectInfoRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_PS_REQUEST_ABSTRACT,
				"LassoIdWsf2PsGetObjectInfoRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_ps_get_object_info_request_new:
 *
 * Creates a new #LassoIdWsf2PsGetObjectInfoRequest object.
 *
 * Return value: a newly created #LassoIdWsf2PsGetObjectInfoRequest object
 **/
LassoIdWsf2PsGetObjectInfoRequest*
lasso_idwsf2_ps_get_object_info_request_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_PS_GET_OBJECT_INFO_REQUEST, NULL);
}
