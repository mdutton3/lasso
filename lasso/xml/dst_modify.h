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

#ifndef __LASSO_DST_MODIFY_H__
#define __LASSO_DST_MODIFY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/disco_encrypted_resource_id.h>
#include <lasso/xml/disco_resource_id.h>
#include <lasso/xml/dst_modification.h>
#include <lasso/xml/xml.h>

#define LASSO_TYPE_DST_MODIFY (lasso_dst_modify_get_type())
#define LASSO_DST_MODIFY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_DST_MODIFY, LassoDstModify))
#define LASSO_DST_MODIFY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_DST_MODIFY, LassoDstModifyClass))
#define LASSO_IS_DST_MODIFY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DST_MODIFY))
#define LASSO_IS_DST_MODIFY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DST_MODIFY))
#define LASSO_DST_MODIFY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
 LASSO_TYPE_DST_MODIFY, LassoDstModifyClass)) 

typedef struct _LassoDstModify LassoDstModify;
typedef struct _LassoDstModifyClass LassoDstModifyClass;

struct _LassoDstModify {
	LassoNode parent;

	/*< public >*/
	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;
	GList *Modification;
	GList *Extension;

	char *id;
	char *itemID;

	char *prefixServiceType;
	char *hrefServiceType;
};

struct _LassoDstModifyClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_dst_modify_get_type(void);

LASSO_EXPORT LassoDstModify* lasso_dst_modify_new(LassoDstModification *modification);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DST_MODIFY_H__ */
