/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
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

#ifndef __LASSO_INTERNALS_H__
#define __LASSO_INTERNALS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
	SNIPPET_NODE,
	SNIPPET_CONTENT,
	SNIPPET_CONTENT_BOOL,
	SNIPPET_CONTENT_INT,
	SNIPPET_TEXT_CHILD,
	SNIPPET_NAME_IDENTIFIER,
	SNIPPET_ATTRIBUTE,
	SNIPPET_ATTRIBUTE_BOOL,
	SNIPPET_ATTRIBUTE_INT,
	SNIPPET_LIST_NODES,
	SNIPPET_LIST_CONTENT,
} SnippetType;

struct XmlSnippetObsolete {
	char *name;
	SnippetType type;
	void **value;
};

struct XmlSnippet {
	char *name;
	SnippetType type;
	guint offset;
};

void init_xml_with_snippets(xmlNode *node, struct XmlSnippetObsolete *snippets);
void build_xml_with_snippets(xmlNode *node, struct XmlSnippetObsolete *snippets);

struct _LassoNodeClassData
{
	struct XmlSnippet *snippets;
	char *node_name;
	xmlNs *ns;
};

void lasso_node_class_set_nodename(LassoNodeClass *klass, char *name);
void lasso_node_class_set_ns(LassoNodeClass *klass, char *href, char *prefix);
void lasso_node_class_add_snippets(LassoNodeClass *klass, struct XmlSnippet *snippets);
void lasso_node_build_xmlNode_from_snippets(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippets);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_INTERNALS_H__ */
