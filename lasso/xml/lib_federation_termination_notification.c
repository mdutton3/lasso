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
#include "../utils.h"
#include "private.h"
#include "lib_federation_termination_notification.h"
#include <libxml/uri.h>

/**
 * SECTION:lib_federation_termination_notification
 * @short_description: &lt;lib:FederationTerminationNotification&gt;
 *
 * <figure><title>Schema fragment for lib:FederationTerminationNotification</title>
 * <programlisting><![CDATA[
 * <xs:element name="FederationTerminationNotification"
 *     type="FederationTerminationNotificationType"/>
 *   <xs:complexType name="FederationTerminationNotificationType">
 *     <xs:complexContent>
 *       <xs:extension base="samlp:RequestAbstractType">
 *         <xs:sequence>
 *           <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *           <xs:element ref="ProviderID"/>
 *           <xs:element ref="saml:NameIdentifier"/>
 *         </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 *
 * <xs:element name="ProviderID" type="md:entityIDType"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION,
		G_STRUCT_OFFSET(LassoLibFederationTerminationNotification, Extension), NULL, NULL,
		NULL},
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibFederationTerminationNotification, ProviderID), NULL, NULL,
		NULL},
	{ "NameIdentifier", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibFederationTerminationNotification, NameIdentifier), NULL,
		LASSO_SAML_ASSERTION_PREFIX, LASSO_SAML_ASSERTION_HREF},
	{ "consent", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibFederationTerminationNotification, consent), NULL, NULL,
		NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static struct QuerySnippet query_snippets[] = {
	{ "RequestID", NULL },
	{ "MajorVersion", NULL },
	{ "MinorVersion", NULL },
	{ "IssueInstant", NULL },
	{ "ProviderID", NULL },
	{ "NameIdentifier/NameQualifier", "NameQualifier" },
	{ "NameIdentifier/Format", "NameFormat" },
	{ "NameIdentifier/content", "NameIdentifier" },
	{ "consent", NULL },
	{ NULL, NULL }
};

static LassoNodeClass *parent_class = NULL;

static gchar*
build_query(LassoNode *node)
{
	LassoLibFederationTerminationNotification *request;
	char *s, *query;
	xmlChar *t;

	request = LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(node);

	query = lasso_node_build_query_from_snippets(node);

	if (request->RelayState) {
		t = xmlURIEscapeStr((xmlChar*)request->RelayState, NULL);
		s = g_strdup_printf((char*)t, "%s&RelayState=%s", query, request->RelayState);
		xmlFree(t);
		lasso_release(query);
		query = s;
	}

	return query;
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibFederationTerminationNotification *request;
	gboolean rc;

	request = LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(node);
	request->NameIdentifier = lasso_saml_name_identifier_new();

	rc = parent_class->init_from_query(node, query_fields);

	if (request->ProviderID == NULL ||
			request->NameIdentifier->content == NULL ||
			request->NameIdentifier->Format == NULL) {
		lasso_node_destroy(LASSO_NODE(request->NameIdentifier));
		request->NameIdentifier = NULL;
		return FALSE;
	}

	return rc;
}




/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibFederationTerminationNotificationClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "FederationTerminationNotification");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	lasso_node_class_add_query_snippets(nclass, query_snippets);
}

GType
lasso_lib_federation_termination_notification_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibFederationTerminationNotificationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibFederationTerminationNotification),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibFederationTerminationNotification", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_federation_termination_notification_new:
 *
 * Creates a new #LassoLibFederationTerminationNotification object.
 *
 * Return value: a newly created #LassoLibFederationTerminationNotification
 *     object
 **/
LassoNode*
lasso_lib_federation_termination_notification_new()
{
	return g_object_new(LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION, NULL);
}


/**
 * lasso_lib_federation_termination_notification_new_full:
 * @providerID: the provider ID doing the notification
 * @nameIdentifier: the name identifier for the federation to terminate.
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibFederationTerminationNotification object and
 * initializes it with the parameters.
 *
 * Return value: a newly created #LassoLibFederationTerminationNotification
 *     object
 **/
LassoNode*
lasso_lib_federation_termination_notification_new_full(char *providerID,
		LassoSamlNameIdentifier *nameIdentifier,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();
	request->sign_type = sign_type;
	request->sign_method = sign_method;

	LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(request)->NameIdentifier =
		g_object_ref(nameIdentifier);

	return LASSO_NODE(request);
}
