/* $Id: subs_notification.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "subs_notification.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:subs_notification
 * @short_description: &lt;subs:Notification&gt;
 *
 * <figure><title>Schema fragment for subs:Notification</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="NotificationType">
 *   <xs:sequence>
 *     <xs:element ref="lu:TestResult" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" use="optional" type="xs:ID"/>
 *   <xs:attribute name="subscriptionID" use="required" type="lu:IDType"/>
 *   <xs:attribute name="expires" use="optional" type="xs:dateTime"/>
 *   <xs:attribute name="endReason" use="optional" type="xs:anyURI"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "TestResult", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SubsNotification, TestResult),
		"LassoIdWsf2UtilTestResult", NULL, NULL },
	{ "id", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsNotification, id), NULL, NULL, NULL},
	{ "subscriptionID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsNotification, subscriptionID), NULL, NULL, NULL},
	{ "expires", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsNotification, expires), NULL, NULL, NULL},
	{ "endReason", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsNotification, endReason), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2SubsNotificationClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Notification");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SUBS_HREF, LASSO_IDWSF2_SUBS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_subs_notification_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SubsNotificationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SubsNotification),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2SubsNotification", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_subs_notification_new:
 *
 * Creates a new #LassoIdWsf2SubsNotification object.
 *
 * Return value: a newly created #LassoIdWsf2SubsNotification object
 **/
LassoIdWsf2SubsNotification*
lasso_idwsf2_subs_notification_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SUBS_NOTIFICATION, NULL);
}
