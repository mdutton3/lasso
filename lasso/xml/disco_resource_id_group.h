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

#ifndef __LASSO_DISCO_RESOURCE_ID_GROUP_H__
#define __LASSO_DISCO_RESOURCE_ID_GROUP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/disco_resource_id.h>
#include <lasso/xml/disco_encrypted_resource_id.h>

#define LASSO_TYPE_DISCO_RESOURCE_ID_GROUP (lasso_disco_resource_id_group_get_type())
#define LASSO_DISCO_RESOURCE_ID_GROUP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
       LASSO_TYPE_DISCO_RESOURCE_ID_GROUP, LassoDiscoResourceIDGroup))
#define LASSO_DISCO_RESOURCE_ID_GROUP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
       LASSO_TYPE_DISCO_RESOURCE_ID_GROUP, LassoDiscoResourceIDGroupClass))
#define LASSO_IS_DISCO_RESOURCE_ID_GROUP(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
       LASSO_TYPE_DISCO_RESOURCE_ID_GROUP))
#define LASSO_IS_DISCO_RESOURCE_ID_GROUP_CLASS(klass) \
       (G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_DISCO_RESOURCE_ID_GROUP))
#define LASSO_DISCO_RESOURCE_ID_GROUP_GET_CLASS(o) \
       (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_RESOURCE_ID_GROUP, \
				   LassoDiscoResourceIDGroupClass))

typedef struct _LassoDiscoResourceIDGroup LassoDiscoResourceIDGroup;
typedef struct _LassoDiscoResourceIDGroupClass LassoDiscoResourceIDGroupClass;

struct _LassoDiscoResourceIDGroup {
	LassoNode parent;

	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;
};

struct _LassoDiscoResourceIDGroupClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_resource_id_group_get_type(void);

LASSO_EXPORT LassoDiscoResourceIDGroup* lasso_disco_resource_id_group_new(void);

LASSO_EXPORT LassoDiscoResourceIDGroup* lasso_disco_resource_id_group_set_resourceID(
	const char *resourceID, const char id);

LASSO_EXPORT LassoDiscoResourceIDGroup* lasso_disco_resource_id_group_set_encryptedResourceID(
	const char *encryptedData, const char *encryptedKey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_RESOURCE_ID_GROUP_H__ */
