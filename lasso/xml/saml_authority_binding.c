/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/saml_authority_binding.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="AuthorityBinding" type="saml:AuthorityBindingType"/>
<complexType name="AuthorityBindingType">
  <attribute name="AuthorityKind" type="QName" use="required"/>
  <attribute name="Location" type="anyURI" use="required"/>
  <attribute name="Binding" type="anyURI" use="required"/>
</complexType>

*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoSamlAuthorityBinding *binding = LASSO_SAML_AUTHORITY_BINDING(node);

	xmlnode = xmlNewNode(NULL, "AuthorityBinding");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX));
	if (binding->AuthorityKind)
		xmlSetProp(xmlnode, "AuthorityKind", binding->AuthorityKind);
	if (binding->Location)
		xmlSetProp(xmlnode, "Location", binding->Location);
	if (binding->Binding)
		xmlSetProp(xmlnode, "Binding", binding->Binding);

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoSamlAuthorityBinding *binding = LASSO_SAML_AUTHORITY_BINDING(node);

	parent_class->init_from_xml(node, xmlnode);
	binding->AuthorityKind = xmlGetProp(xmlnode, "AuthorityKind");
	binding->Location = xmlGetProp(xmlnode, "Location");
	binding->Binding = xmlGetProp(xmlnode, "Binding");
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlAuthorityBinding *node)
{
	node->AuthorityKind = NULL;
	node->Location = NULL;
	node->Binding = NULL;
}

static void
class_init(LassoSamlAuthorityBindingClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_authority_binding_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAuthorityBindingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAuthorityBinding),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAuthorityBinding", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_authority_binding_new:
 * 
 * Creates a new <saml:AuthorityBinding> node object.
 * 
 * Return value: the new @LassoSamlAuthorityBinding
 **/
LassoNode*
lasso_saml_authority_binding_new()
{
	return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_AUTHORITY_BINDING, NULL));
}

