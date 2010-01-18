/* $Id: misc_text_node.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#include "misc_text_node.h"

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "content", SNIPPET_TEXT_CHILD,
		G_STRUCT_OFFSET(LassoMiscTextNode, content) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	xmlNode *t = xmlnode->children;

	xmlSetNs(xmlnode, ns);
	while (t) {
		if (t->type == XML_ELEMENT_NODE && t->ns == NULL)
			insure_namespace(t, ns);
		t = t->next;
	}
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	xmlNs *ns;
	
	if (LASSO_MISC_TEXT_NODE(node)->text_child) {
		return xmlNewText((xmlChar*)(LASSO_MISC_TEXT_NODE(node)->content));
	}

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)LASSO_MISC_TEXT_NODE(node)->name);
	ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_MISC_TEXT_NODE(node)->ns_href,
			(xmlChar*)LASSO_MISC_TEXT_NODE(node)->ns_prefix);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoMiscTextNode *n = LASSO_MISC_TEXT_NODE(node);
	int rc;

	if (xmlnode->type == XML_TEXT_NODE) {
		n->text_child = TRUE;
		n->content = g_strdup((char*)(xmlnode->content));
		return 0;
	}

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	n->ns_href = g_strdup((char*)xmlnode->ns->href);
	n->ns_prefix = g_strdup((char*)xmlnode->ns->prefix);
	n->name = g_strdup((char*)xmlnode->name);

	return 0;
}

static void
finalize(GObject *object)
{
	LassoMiscTextNode *t = LASSO_MISC_TEXT_NODE(object);

	g_free(t->name);
	g_free(t->ns_href);
	g_free(t->ns_prefix);

	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(t));
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoMiscTextNode *node)
{
	node->content = NULL;

	node->name = NULL;
	node->ns_href = NULL;
	node->ns_prefix = NULL;
	node->text_child = FALSE;
}

static void
class_init(LassoMiscTextNodeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);

	G_OBJECT_CLASS(nclass)->finalize = finalize;

	lasso_node_class_set_nodename(nclass, "XXX");
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_misc_text_node_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoMiscTextNodeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoMiscTextNode),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoMiscTextNode", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_misc_text_node_new:
 *
 * Creates a new #LassoMiscTextNode object.
 *
 * Return value: a newly created #LassoMiscTextNode object
 **/
LassoNode*
lasso_misc_text_node_new()
{
	return g_object_new(LASSO_TYPE_MISC_TEXT_NODE, NULL);
}


/**
 * lasso_misc_text_node_new_with_string:
 * @content: 
 *
 * Creates a new #LassoMiscTextNode object and initializes it
 * with @content.
 *
 * Return value: a newly created #LassoMiscTextNode object
 **/
LassoNode*
lasso_misc_text_node_new_with_string(char *content)
{
	LassoMiscTextNode *object;
	object = g_object_new(LASSO_TYPE_MISC_TEXT_NODE, NULL);
	object->content = g_strdup(content);
	return LASSO_NODE(object);
}

