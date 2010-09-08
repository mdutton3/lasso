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

#include "private.h"
#include "soap_binding_provider.h"
#include "./idwsf_strings.h"

/**
 * SECTION:soap_binding_provider
 * @short_description: &lt;soapbinding:ProviderType&gt;
 *
 * <figure><title>Schema fragment for soapbinding:ProviderType</title>
 * <programlisting><![CDATA[
 * <xs:complexType name="ProviderType">
 *   <xs:attribute name="providerID" type="xs:anyURI" use="required"/>
 *   <xs:attribute name="affiliationID" type="xs: nyURI" use="optional"/>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 *   <xs:attribute ref="S:mustUnderstand" use="optional"/>
 *   <xs:attribute ref="S:actor" use="optional"/>
 * </xs:complexType>
 * <xs:element name="Provider" type="ProviderType"/>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "providerID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingProvider, providerID), NULL, NULL, NULL},
	{ "affiliationID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingProvider, affiliationID), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSoapBindingProvider, id), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingProvider, mustUnderstand), NULL, NULL, NULL},
	{ "actor", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSoapBindingProvider, actor), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapBindingProviderClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Provider");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_BINDING_HREF, LASSO_SOAP_BINDING_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_binding_provider_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapBindingProviderClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapBindingProvider),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapBindingProvider", &this_info, 0);
	}
	return this_type;
}

LassoSoapBindingProvider*
lasso_soap_binding_provider_new(const gchar *providerID)
{
	LassoSoapBindingProvider *node;

	node = g_object_new(LASSO_TYPE_SOAP_BINDING_PROVIDER, NULL);

	node->providerID = g_strdup(providerID);

	return node;
}
