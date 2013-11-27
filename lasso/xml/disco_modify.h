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

#ifndef __LASSO_DISCO_MODIFY_H__
#define __LASSO_DISCO_MODIFY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "disco_resource_id.h"
#include "disco_encrypted_resource_id.h"

#define LASSO_TYPE_DISCO_MODIFY (lasso_disco_modify_get_type())
#define LASSO_DISCO_MODIFY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_MODIFY, LassoDiscoModify))
#define LASSO_DISCO_MODIFY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_MODIFY, LassoDiscoModifyClass))
#define LASSO_IS_DISCO_MODIFY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_MODIFY))
#define LASSO_IS_DISCO_MODIFY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_MODIFY))
#define LASSO_DISCO_MODIFY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_MODIFY, LassoDiscoModifyClass))

typedef struct _LassoDiscoModify LassoDiscoModify;
typedef struct _LassoDiscoModifyClass LassoDiscoModifyClass;

struct _LassoDiscoModify {
	LassoNode parent;

	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

	GList *InsertEntry; /* of LassoNode */
	GList *RemoveEntry; /* of LassoNode */

	char *id;
};

struct _LassoDiscoModifyClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_modify_get_type (void);

LASSO_EXPORT LassoDiscoModify* lasso_disco_modify_new (void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_MODIFY_H__ */
