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

#ifndef __LASSO_IS_INTERACTION_REQUEST_H__
#define __LASSO_IS_INTERACTION_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "disco_encrypted_resource_id.h"
#include "disco_resource_id.h"
#include "is_inquiry.h"
#include "xml.h"


#define LASSO_TYPE_IS_INTERACTION_REQUEST (lasso_is_interaction_request_get_type())
#define LASSO_IS_INTERACTION_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IS_INTERACTION_REQUEST, \
				    LassoIsInteractionRequest))
#define LASSO_IS_INTERACTION_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IS_INTERACTION_REQUEST, \
				 LassoIsInteractionRequestClass))
#define LASSO_IS_IS_INTERACTION_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IS_INTERACTION_REQUEST))
#define LASSO_IS_IS_INTERACTION_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_IS_INTERACTION_REQUEST))
#define LASSO_IS_INTERACTION_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IS_INTERACTION_REQUEST, \
				    LassoIsInteractionRequestClass))

typedef struct _LassoIsInteractionRequest LassoIsInteractionRequest;
typedef struct _LassoIsInteractionRequestClass LassoIsInteractionRequestClass;

struct _LassoIsInteractionRequest {
	LassoNode parent;

	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;
	GList *Inquiry; /* of LassoNode */
	/* TODO : ds:KeyInfo */

	char *id;
	char *language;
	int maxInteractTime;
	/* TODO : signed */
};

struct _LassoIsInteractionRequestClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_is_interaction_request_get_type(void);

LASSO_EXPORT LassoIsInteractionRequest* lasso_is_interaction_request_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IS_INTERACTION_REQUEST_H__ */
