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

#include "../private.h"
#include "saml2_key_info_confirmation_data_type.h"
#include "../../registry.h"
#include "../dsig/ds_key_info.h"
#include "../../utils.h"

/**
 * SECTION:saml2_key_info_confirmation_data_type
 * @short_description: &lt;saml2:KeyInfoConfirmationDataType&gt;
 *
 * <figure><title>Schema fragment for saml2:KeyInfoConfirmationDataType</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="KeyInfoConfirmationDataTypeType" mixed="true">
 *   <complexContent>
 *     <restriction base="anyType">
 *       <sequence>
 *         <any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *       </sequence>
 *       <attribute name="NotBefore" type="dateTime" use="optional"/>
 *       <attribute name="NotOnOrAfter" type="dateTime" use="optional"/>
 *       <attribute name="Recipient" type="anyURI" use="optional"/>
 *       <attribute name="InResponseTo" type="NCName" use="optional"/>
 *       <attribute name="Address" type="string" use="optional"/>
 *       <anyAttribute namespace="##other" processContents="lax"/>
 *     </restriction>
 *   </complexContent>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

struct _LassoSaml2KeyInfoConfirmationDataTypePrivate {
	GList *KeyInfo;
};

static struct XmlSnippet schema_snippets[] = {
	{ "KeyInfo", SNIPPET_LIST_NODES|SNIPPET_PRIVATE,
		G_STRUCT_OFFSET(LassoSaml2KeyInfoConfirmationDataTypePrivate, KeyInfo),
		"LassoDsKeyInfo", LASSO_DS_PREFIX, LASSO_DS_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

#define LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE, LassoSaml2KeyInfoConfirmationDataTypePrivate))

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSaml2KeyInfoConfirmationDataType *saml2_key_info_confirmation_data_type)
{
	saml2_key_info_confirmation_data_type->private_data =
		LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_GET_PRIVATE(
				saml2_key_info_confirmation_data_type);
}

static void
class_init(LassoSaml2KeyInfoConfirmationDataTypeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->node_data->xsi_sub_type = TRUE;
	lasso_node_class_set_nodename(nclass, "KeyInfoConfirmationDataType");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(LassoSaml2KeyInfoConfirmationDataTypePrivate));
}

GType
lasso_saml2_key_info_confirmation_data_type_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2KeyInfoConfirmationDataTypeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2KeyInfoConfirmationDataType),
			0,
			(GInstanceInitFunc)instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML2_SUBJECT_CONFIRMATION_DATA,
				"LassoSaml2KeyInfoConfirmationDataType", &this_info, 0);
		lasso_registry_default_add_direct_mapping(LASSO_SAML2_ASSERTION_HREF,
				"KeyInfoConfirmationDataType", LASSO_LASSO_HREF,
				"LassoSaml2KeyInfoConfirmationDataType");
	}
	return this_type;
}

/**
 * lasso_saml2_key_info_confirmation_data_type_new:
 *
 * Creates a new #LassoSaml2KeyInfoConfirmationDataType object.
 *
 * Return value: a newly created #LassoSaml2KeyInfoConfirmationDataType object
 **/
LassoNode*
lasso_saml2_key_info_confirmation_data_type_new()
{
	return g_object_new(LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE, NULL);
}

/**
 * lasso_saml2_key_info_confirmation_data_type_get_key_info:
 * @kicdt: a #LassoSaml2KeyInfoConfirmationDataType object.
 *
 * Return the list of KeyInfo node contained in the saml2:SubjectConfirmationData of type
 * saml2:KeyInfoConfirmationDataType.
 *
 * Return value:(element-type LassoDsKeyInfo)(transfer none): a list of #LassoDsKeyInfo objects.
 */
GList*
lasso_saml2_key_info_confirmation_data_type_get_key_info(
		LassoSaml2KeyInfoConfirmationDataType *kicdt)
{
	lasso_return_val_if_fail(LASSO_IS_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE(kicdt), NULL);

	return kicdt->private_data->KeyInfo;
}

/**
 * lasso_saml2_key_info_confirmation_data_type_set_key_info:
 * @kicdt: a #LassoSaml2KeyInfoConfirmationDataType object.
 * @key_infos:(tranfer none)(element-type LassoDsKeyInfo): a list of #LassoDsKeyInfo object.
 *
 * Set the list of ds:KeyInfo nodes for the saml2:SubjectConfirmationData of type
 * saml2:KeyInfoConfirmationDataType.
 */
void
lasso_saml2_key_info_confirmation_data_type_set_key_info(
		LassoSaml2KeyInfoConfirmationDataType *kicdt,
		GList *key_infos)
{
	lasso_return_if_fail(LASSO_IS_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE(kicdt));

	lasso_assign_list_of_gobjects(
			kicdt->private_data->KeyInfo,
			key_infos);
}
