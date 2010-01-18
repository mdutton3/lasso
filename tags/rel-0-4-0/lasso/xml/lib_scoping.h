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

#ifndef __LASSO_LIB_SCOPING_H__
#define __LASSO_LIB_SCOPING_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/lib_idp_list.h>

#define LASSO_TYPE_LIB_SCOPING (lasso_lib_scoping_get_type())
#define LASSO_LIB_SCOPING(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_SCOPING, LassoLibScoping))
#define LASSO_LIB_SCOPING_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_SCOPING, LassoLibScopingClass))
#define LASSO_IS_LIB_SCOPING(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_SCOPING))
#define LASSO_IS_LIB_SCOPING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_SCOPING))
#define LASSO_LIB_SCOPING_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_SCOPING, LassoLibScopingClass)) 

typedef struct _LassoLibScoping LassoLibScoping;
typedef struct _LassoLibScopingClass LassoLibScopingClass;

struct _LassoLibScoping {
  LassoNode parent;
  /*< private >*/
};

struct _LassoLibScopingClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_lib_scoping_get_type(void);
LASSO_EXPORT LassoNode* lasso_lib_scoping_new(void);

LASSO_EXPORT void lasso_lib_scoping_set_proxyCount (LassoLibScoping *node,
						    gint             proxyCount);

LASSO_EXPORT void lasso_lib_scoping_set_idpList    (LassoLibScoping *node,
						    LassoLibIDPList *idpList);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_SCOPING_H__ */
