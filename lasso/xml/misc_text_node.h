/* $Id: misc_text_node.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_MISC_TEXT_NODE_H__
#define __LASSO_MISC_TEXT_NODE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_MISC_TEXT_NODE (lasso_misc_text_node_get_type())
#define LASSO_MISC_TEXT_NODE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_MISC_TEXT_NODE, \
				LassoMiscTextNode))
#define LASSO_MISC_TEXT_NODE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_MISC_TEXT_NODE, \
				LassoMiscTextNodeClass))
#define LASSO_IS_MISC_TEXT_NODE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_MISC_TEXT_NODE))
#define LASSO_IS_MISC_TEXT_NODE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_MISC_TEXT_NODE))
#define LASSO_MISC_TEXT_NODE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_MISC_TEXT_NODE, \
				LassoMiscTextNodeClass))

typedef struct _LassoMiscTextNode LassoMiscTextNode;
typedef struct _LassoMiscTextNodeClass LassoMiscTextNodeClass;


struct _LassoMiscTextNode {
	LassoNode parent;

	/*< public >*/
	/* elements */
	char *content;

	char *name;
	char *ns_href;
	char *ns_prefix;
	gboolean text_child;
};


struct _LassoMiscTextNodeClass {
	LassoNodeClass parent;
};

LASSO_EXPORT void lasso_misc_text_node_set_xml_content(LassoMiscTextNode *misc_text_node,
		xmlNode *node);

LASSO_EXPORT xmlNode* lasso_misc_text_node_get_xml_content(LassoMiscTextNode *misc_text_node);

LASSO_EXPORT GType lasso_misc_text_node_get_type(void);

LASSO_EXPORT LassoNode* lasso_misc_text_node_new(void);

LASSO_EXPORT LassoMiscTextNode* lasso_misc_text_node_new_with_string(const char *content);

LASSO_EXPORT LassoMiscTextNode* lasso_misc_text_node_new_with_xml_node(xmlNode *xml_node);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_MISC_TEXT_NODE_H__ */
