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

#include <lasso/xml/saml_name_identifier.h>
#include <libxml/uri.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="NameIdentifier" type="saml:NameIdentifierType"/>
<complexType name="NameIdentifierType">
  <simpleContent>
    <extension base="string">
      <attribute name="NameQualifier" type="string" use="optional"/>
      <attribute name="Format" type="anyURI" use="optional"/>
    </extension>
  </simpleContent>
</complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar*
lasso_saml_name_identifier_build_query(LassoSamlNameIdentifier *identifier,
		char *prefix, char *prefix_content)
{
	GString *s;
	char *str;
	xmlChar *t;

	s = g_string_new("");
	if (identifier->NameQualifier) {
		t = xmlURIEscapeStr(identifier->NameQualifier, NULL);
		g_string_append_printf(s, "&%sNameQualifier=%s", prefix, t);
		xmlFree(t);
	}
	if (identifier->Format) {
		t = xmlURIEscapeStr(identifier->Format, NULL);
		g_string_append_printf(s, "&%sNameFormat=%s", prefix, t);
		xmlFree(t);
	}
	if (identifier->content) {
		t = xmlURIEscapeStr(identifier->content, NULL);
		g_string_append_printf(s, "&%sNameIdentifier=%s", prefix_content, t);
		xmlFree(t);
	}

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoSamlNameIdentifier *identifier = LASSO_SAML_NAME_IDENTIFIER(node);

	xmlnode = xmlNewNode(NULL, "NameIdentifier");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX));
	xmlAddChild(xmlnode, xmlNewText(identifier->content));
	if (identifier->Format)
		xmlSetProp(xmlnode, "Format", identifier->Format);
	if (identifier->NameQualifier)
		xmlSetProp(xmlnode, "NameQualifier", identifier->NameQualifier);

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoSamlNameIdentifier *identifier = LASSO_SAML_NAME_IDENTIFIER(node);

        parent_class->init_from_xml(node, xmlnode);
	identifier->content = xmlNodeGetContent(xmlnode);
	identifier->Format = xmlGetProp(xmlnode, "Format");
	identifier->NameQualifier = xmlGetProp(xmlnode, "NameQualifier");
}

static gchar*
build_query(LassoNode *node)
{
	return lasso_saml_name_identifier_build_query(LASSO_SAML_NAME_IDENTIFIER(node), "", "");
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlNameIdentifier *node)
{
	node->NameQualifier = NULL;
	node->Format = NULL;
	node->content = NULL;
}

static void
class_init(LassoSamlNameIdentifierClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
}

GType
lasso_saml_name_identifier_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlNameIdentifierClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlNameIdentifier),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlNameIdentifier", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_name_identifier_new:
 * 
 * Creates a new <saml:NameIdentifier> node object.
 * 
 * Return value: the new @LassoSamlNameIdentifier
 **/
LassoSamlNameIdentifier*
lasso_saml_name_identifier_new()
{
	return g_object_new(LASSO_TYPE_SAML_NAME_IDENTIFIER, NULL);
}


LassoSamlNameIdentifier*
lasso_saml_name_identifier_new_from_xmlNode(xmlNode *xmlnode)
{
	LassoNode *node;

	node = g_object_new(LASSO_TYPE_SAML_NAME_IDENTIFIER, NULL);
	lasso_node_init_from_xml(node, xmlnode);
	return LASSO_SAML_NAME_IDENTIFIER(node);
}

