/* $Id: disco_requested_service.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#include "disco_requested_service.h"

/**
 * SECTION:disco_requested_service
 * @short_description: &lt;disco:RequestedService&gt;
 *
 * <figure><title>Schema fragment for disco:RequestedService</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="RequestedServiceType">
 *   <xs:sequence>
 *     <xs:element ref="ServiceType" minOccurs="0" maxOccurs="unbounded" />
 *     
 *     <xs:element ref="ProviderID" minOccurs="0" maxOccurs="unbounded" />
 *     
 *     <xs:element ref="Options" minOccurs="0" maxOccurs="unbounded"/>
 *     
 *     <xs:element ref="SecurityMechID" minOccurs="0" maxOccurs="unbounded"/>
 *     
 *     <xs:element ref="Framework" minOccurs="0" maxOccurs="unbounded"/>
 *     
 *     <xs:element ref="Action" minOccurs="0" maxOccurs="unbounded"/>
 *     
 *     <xs:any namespace="##other"
 *       processContents="lax"
 *       minOccurs="0"
 *       maxOccurs="unbounded"/>
 *       
 *     </xs:sequence>
 *     
 *     <xs:attribute name="reqID" type="xs:string" use="optional" />
 *     <xs:attribute name="resultsType" type="xs:string" use="optional" />
 *     
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "ServiceType", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, ServiceType) },
	{ "ProviderID", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, ProviderID) },
	{ "Options", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, Options),
		"LassoIdWsf2DiscoOptions" },
	{ "SecurityMechID", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, SecurityMechID) },
	{ "Framework", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, Framework) },
	{ "Action", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, Action) },
	{ "", SNIPPET_NODE | SNIPPET_ANY | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, any) },
	{ "reqID", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, reqID) },
	{ "resultsType", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoRequestedService, resultsType) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DiscoRequestedService *node)
{
	node->ServiceType = NULL;
	node->ProviderID = NULL;
	node->Options = NULL;
	node->SecurityMechID = NULL;
	node->Framework = NULL;
	node->Action = NULL;
	node->any = NULL;
	node->reqID = NULL;
	node->resultsType = NULL;
}

static void
class_init(LassoIdWsf2DiscoRequestedServiceClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RequestedService");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF, LASSO_IDWSF2_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_requested_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoRequestedServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoRequestedService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoRequestedService", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_requested_service_new:
 *
 * Creates a new #LassoIdWsf2DiscoRequestedService object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoRequestedService object
 **/
LassoIdWsf2DiscoRequestedService*
lasso_idwsf2_disco_requested_service_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_REQUESTED_SERVICE, NULL);
}
