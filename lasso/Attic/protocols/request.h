/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __LASSO_REQUEST_H__
#define __LASSO_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/samlp_request.h>

#define LASSO_TYPE_REQUEST (lasso_request_get_type())
#define LASSO_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_REQUEST, LassoRequest))
#define LASSO_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_REQUEST, LassoRequestClass))
#define LASSO_IS_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_REQUEST))
#define LASSP_IS_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_REQUEST))
#define LASSO_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_REQUEST, LassoRequestClass)) 

typedef struct _LassoRequest LassoRequest;
typedef struct _LassoRequestClass LassoRequestClass;

struct _LassoRequest {
  LassoSamlpRequest parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoRequestClass {
  LassoSamlpRequestClass parent;
};

LASSO_EXPORT GType      lasso_request_get_type (void);

LASSO_EXPORT LassoNode* lasso_request_new      (const xmlChar *assertionArtifact);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_REQUEST_H__ */
