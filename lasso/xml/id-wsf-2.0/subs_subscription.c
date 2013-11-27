/* $Id: subs_subscription.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "subs_subscription.h"
#include "idwsf2_strings.h"

/**
 * SECTION:subs_subscription
 * @short_description: &lt;subs:Subscription&gt;
 *
 * <figure><title>Schema fragment for subs:Subscription</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="SubscriptionType">
 *   <xs:sequence>
 *     <xs:element ref="subs:RefItem" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element ref="lu:Extension" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="subscriptionID" use="required" type="lu:IDType"/>
 *   <xs:attribute name="notifyToRef" use="required" type="xs:anyURI"/>
 *   <xs:attribute name="adminNotifyToRef" use="optional" type="xs:anyURI"/>
 *   <xs:attribute name="starts" use="optional" type="xs:dateTime"/>
 *   <xs:attribute name="expires" use="optional" type="xs:dateTime"/>
 *   <xs:attribute name="id" use="optional" type="xs:ID"/>
 *   <xs:attribute name="includeData" use="optional">
 *     <xs:simpleType>
 *       <xs:restriction base="xs:string">
 *         <xs:enumeration value="Yes"/>
 *         <xs:enumeration value="No"/>
 *         <xs:enumeration value="YesWithCommonAttributes"/>
 *       </xs:restriction>
 *     </xs:simpleType>
 *   </xs:attribute>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "RefItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, RefItem), NULL, NULL, NULL},
	{ "Extension", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, Extension),
		"LassoIdWsf2Utilextension", LASSO_IDWSF2_UTIL_PREFIX, LASSO_IDWSF2_UTIL_HREF},
	{ "subscriptionID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, subscriptionID), NULL, NULL, NULL},
	{ "notifyToRef", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, notifyToRef), NULL, NULL, NULL},
	{ "adminNotifyToRef", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, adminNotifyToRef), NULL, NULL, NULL},
	{ "starts", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, starts), NULL, NULL, NULL},
	{ "expires", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, expires), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, id), NULL, NULL, NULL},
	{ "includeData", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsSubscription, includeData), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2SubsSubscriptionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Subscription");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SUBS_HREF, LASSO_IDWSF2_SUBS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_subs_subscription_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SubsSubscriptionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SubsSubscription),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2SubsSubscription", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_subs_subscription_new:
 *
 * Creates a new #LassoIdWsf2SubsSubscription object.
 *
 * Return value: a newly created #LassoIdWsf2SubsSubscription object
 **/
LassoIdWsf2SubsSubscription*
lasso_idwsf2_subs_subscription_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SUBS_SUBSCRIPTION, NULL);
}
