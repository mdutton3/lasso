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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_DISCO_ENCRYPTED_RESOURCE_ID_H__
#define __LASSO_DISCO_ENCRYPTED_RESOURCE_ID_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID (lasso_disco_encrypted_resource_id_get_type())
#define LASSO_DISCO_ENCRYPTED_RESOURCE_ID(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID, LassoDiscoEncryptedResourceID))
#define LASSO_DISCO_ENCRYPTED_RESOURCE_ID_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID, \
				 LassoDiscoEncryptedResourceIDClass))
#define LASSO_IS_DISCO_ENCRYPTED_RESOURCE_ID(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID))
#define LASSO_IS_DISCO_ENCRYPTED_RESOURCE_ID_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID))
#define LASSO_DISCO_ENCRYPTED_RESOURCE_ID_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID, \
				    LassoDiscoEncryptedResourceIDClass))

typedef struct _LassoDiscoEncryptedResourceID LassoDiscoEncryptedResourceID;
typedef struct _LassoDiscoEncryptedResourceIDClass LassoDiscoEncryptedResourceIDClass;

struct _LassoDiscoEncryptedResourceID {
	LassoNode parent;

	xmlNode *EncryptedData;
	GList *EncryptedKey; /* of xmlNode* */
};

struct _LassoDiscoEncryptedResourceIDClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_encrypted_resource_id_get_type(void);

LASSO_EXPORT LassoDiscoEncryptedResourceID* lasso_disco_encrypted_resource_id_new();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_ENCRYPTED_RESOURCE_ID_H__ */
