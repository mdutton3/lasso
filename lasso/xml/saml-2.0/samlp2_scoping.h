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

#ifndef __LASSO_SAMLP2_SCOPING_H__
#define __LASSO_SAMLP2_SCOPING_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp2_idp_list.h"

#define LASSO_TYPE_SAMLP2_SCOPING (lasso_samlp2_scoping_get_type())
#define LASSO_SAMLP2_SCOPING(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_SCOPING, \
				LassoSamlp2Scoping))
#define LASSO_SAMLP2_SCOPING_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_SCOPING, \
				LassoSamlp2ScopingClass))
#define LASSO_IS_SAMLP2_SCOPING(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_SCOPING))
#define LASSO_IS_SAMLP2_SCOPING_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_SCOPING))
#define LASSO_SAMLP2_SCOPING_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_SCOPING, \
				LassoSamlp2ScopingClass))

typedef struct _LassoSamlp2Scoping LassoSamlp2Scoping;
typedef struct _LassoSamlp2ScopingClass LassoSamlp2ScopingClass;


struct _LassoSamlp2Scoping {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoSamlp2IDPList *IDPList;
	char *RequesterID;
	/* attributes */
	char *ProxyCount;
};


struct _LassoSamlp2ScopingClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_samlp2_scoping_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_scoping_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_SCOPING_H__ */
