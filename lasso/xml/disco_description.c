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
#include "disco_description.h"
#include "idwsf_strings.h"
#include "../id-wsf/wsf_utils.h"
#include "../utils.h"

/**
 * SECTION:disco_description
 * @short_description: &lt;disco:DescriptionType&gt;
 *
 * <figure><title>Schema fragment for disco:DescriptionType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="DescriptionType">
 *   <xs:sequence>
 *     <xs:element name="SecurityMechID" type="xs:anyURI" minOccurs="1" maxOccurs="unbounded"/>
 *     <xs:element name="CredentialRef" type="xs:IDREF" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:choice>
 *       <xs:group ref="WsdlRef"/>
 *       <xs:group ref="BriefSoapHttpDescription"/>
 *     </xs:choice>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID"/>
 * </xs:complexType>
 *
 * <xs:group name="WsdlRef">
 *   <xs:sequence>
 *     <xs:element name="WsdlURI" type="xs:anyURI"/>
 *     <xs:element name="ServiceNameRef" type="xs:QName"/>
 *   </xs:sequence>
 * </xs:group>
 *
 * <xs:group name="BriefSoapHttpDescription">
 *   <xs:sequence>
 *     <xs:element name="Endpoint" type="xs:anyURI"/>
 *     <xs:element name="SoapAction" type="xs:anyURI" minOccurs="0"/>
 *   </xs:sequence>
 * </xs:group>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "SecurityMechID", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoDiscoDescription, SecurityMechID), NULL, NULL, NULL},
	{ "CredentialRef", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoDiscoDescription, CredentialRef), NULL, NULL, NULL},
	{ "WsdlURI", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDiscoDescription, WsdlURI), NULL, NULL, NULL},
	{ "ServiceNameRef", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoDiscoDescription, ServiceNameRef), NULL, NULL, NULL},
	{ "Endpoint", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDiscoDescription, Endpoint), NULL, NULL, NULL},
	{ "SoapAction", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDiscoDescription, SoapAction), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDiscoDescription, id), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoDescriptionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Description");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_description_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoDescriptionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoDescription),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoDescription", &this_info, 0);
	}
	return this_type;
}

LassoDiscoDescription*
lasso_disco_description_new()
{
	LassoDiscoDescription *description;

	description = g_object_new(LASSO_TYPE_DISCO_DESCRIPTION, NULL);

	return description;
}

LassoDiscoDescription*
lasso_disco_description_new_with_WsdlRef(const gchar *securityMechID,
		const gchar *wsdlURI,
		const gchar *serviceNameRef)
{
	LassoDiscoDescription *description;

	g_return_val_if_fail(securityMechID != NULL, NULL);
	g_return_val_if_fail(wsdlURI != NULL, NULL);
	g_return_val_if_fail(serviceNameRef != NULL, NULL);

	description = g_object_new(LASSO_TYPE_DISCO_DESCRIPTION, NULL);

	description->SecurityMechID = g_list_append(description->SecurityMechID,
			g_strdup(securityMechID));
	description->WsdlURI = g_strdup(wsdlURI);
	description->ServiceNameRef = g_strdup(serviceNameRef);

	return description;
}

LassoDiscoDescription*
lasso_disco_description_new_with_BriefSoapHttpDescription(const gchar *securityMechID,
		const gchar *endpoint,
		const gchar *soapAction)
{
	LassoDiscoDescription *description;

	g_return_val_if_fail(securityMechID != NULL, NULL);
	g_return_val_if_fail(endpoint != NULL, NULL);

	description = g_object_new(LASSO_TYPE_DISCO_DESCRIPTION, NULL);

	description->SecurityMechID = g_list_append(description->SecurityMechID,
			g_strdup(securityMechID));
	description->Endpoint = g_strdup(endpoint);
	if (soapAction != NULL) {
		description->SoapAction = g_strdup(soapAction);
	}

	return description;
}

LassoDiscoDescription*
lasso_disco_description_copy(LassoDiscoDescription *description)
{
	LassoDiscoDescription *newDescription;
	GList *securityMechIds, *credentialRefs;

	newDescription = g_object_new(LASSO_TYPE_DISCO_DESCRIPTION, NULL);

	securityMechIds = description->SecurityMechID;
	while (securityMechIds) {
		newDescription->SecurityMechID = g_list_append(newDescription->SecurityMechID,
				g_strdup(securityMechIds->data));
		securityMechIds = securityMechIds->next;
	}

	credentialRefs = description->CredentialRef;
	while (credentialRefs) {
		newDescription->CredentialRef = g_list_append(newDescription->CredentialRef,
				g_strdup(credentialRefs->data));
		credentialRefs = credentialRefs->next;
	}

	newDescription->WsdlURI = g_strdup(description->WsdlURI);
	newDescription->ServiceNameRef = g_strdup(description->ServiceNameRef);

	if (description->Endpoint) {
		newDescription->Endpoint = g_strdup(description->Endpoint);
	}
	if (description->SoapAction) {
		newDescription->SoapAction = g_strdup(description->SoapAction);
	}

	if (description->id) {
		newDescription->id = g_strdup(description->id);
	}

	return newDescription;
}

/**
 * lasso_disco_description_has_saml_authentication:
 * @profile: a #LassoDiscoDescription
 *
 * Checks if the given description supports any security mechanism using
 * SAML authentication.
 *
 * Returns: %TRUE if SAML is supported by the service description, FALSE if it
 * is not supported of if description is not a valid #LassoDiscoDescription.
 */
gboolean
lasso_disco_description_has_saml_authentication(LassoDiscoDescription *description)
{
	GList *iter;
	gchar *security_mech_id;

	lasso_return_val_if_invalid_param(DISCO_DESCRIPTION, description,
			FALSE);

	iter = description->SecurityMechID;
	while (iter) {
		security_mech_id = iter->data;
		if (lasso_security_mech_id_is_saml_authentication(
				security_mech_id)) {
			return TRUE;
		}
		iter = g_list_next(iter);
	}

	return FALSE;
}

/**
 * lasso_disco_description_has_x509_authentication:
 * @profile: a #LassoDiscoDescription
 *
 * Checks if the given description supports any security mechanism using
 * X509 authentication.
 *
 * Returns: %TRUE if X509 is supported by the service description, FALSE if it
 * is not supported of if description is not a valid #LassoDiscoDescription.
 */
gboolean
lasso_disco_description_has_x509_authentication(LassoDiscoDescription *description)
{
	GList *iter;
	gchar *security_mech_id;

	lasso_return_val_if_invalid_param(DISCO_DESCRIPTION, description,
			FALSE);

	iter = description->SecurityMechID;
	while (iter) {
		security_mech_id = iter->data;
		if (lasso_security_mech_id_is_x509_authentication(
				security_mech_id)) {
			return TRUE;
		}
		iter = g_list_next(iter);
	}

	return FALSE;
}

