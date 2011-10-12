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

#include "../private.h"
#include "saml2_key_info_confirmation_data_type.h"
#include "../../registry.h"
#include "../ds_key_info.h"
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


static struct XmlSnippet schema_snippets[] = {
	{ "KeyInfo", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSaml2KeyInfoConfirmationDataType, KeyInfo), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static xmlNs *
ensure_namespace(xmlNode *node, const xmlChar *href, const xmlChar *prefix)
{
	xmlNs *ns;

	ns = xmlSearchNsByHref(node->doc, node, href);
	if (! ns) {
		ns = xmlNewNs(node, href, prefix);
		xmlSetNs(node, ns);
	}
	return ns;
}

static void
set_qname_attribue(xmlNode *node, xmlChar *attribute_name, const xmlChar *name, const
		xmlChar *href, const xmlChar *prefix) {
	xmlNs *type_ns;
	xmlNs *xsi_ns;
	xmlChar *value;

	xsi_ns = ensure_namespace(node, BAD_CAST LASSO_XSI_HREF, BAD_CAST LASSO_XSI_PREFIX);
	type_ns = ensure_namespace(node, href, prefix);
	value = BAD_CAST g_strdup_printf("%s:%s", type_ns->prefix, name);
	xmlSetNsProp(node, xsi_ns, attribute_name, value);
	lasso_release_string(value);
}

static void
set_xsi_type(xmlNode *node, const xmlChar *type, const xmlChar *href, const xmlChar *prefix) {
	set_qname_attribue(node, BAD_CAST "type", type, href, prefix);
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode = NULL;

	/* add xsi:type="KeyInfoConfirmationDataType" */
	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	set_xsi_type(xmlnode,
			BAD_CAST "KeyInfoConfirmationDataType",
			BAD_CAST LASSO_SAML2_ASSERTION_HREF,
			BAD_CAST LASSO_SAML2_ASSERTION_PREFIX);

	return xmlnode;
}


static void
class_init(LassoSaml2KeyInfoConfirmationDataTypeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->get_xmlNode = get_xmlNode;
	lasso_node_class_add_snippets(nclass, schema_snippets);
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
			NULL,
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
