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

#ifndef __LASSO_RESPONSE_H__
#define __LASSO_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/samlp_response.h>

#define LASSO_TYPE_RESPONSE (lasso_response_get_type())
#define LASSO_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_RESPONSE, LassoResponse))
#define LASSO_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_RESPONSE, LassoResponseClass))
#define LASSO_IS_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_RESPONSE))
#define LASSP_IS_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_RESPONSE))
#define LASSO_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_RESPONSE, LassoResponseClass)) 

typedef struct _LassoResponse LassoResponse;
typedef struct _LassoResponseClass LassoResponseClass;

struct _LassoResponse {
  LassoSamlpResponse parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoResponseClass {
  LassoSamlpResponseClass parent;
};

LASSO_EXPORT GType      lasso_response_get_type        (void);

LASSO_EXPORT LassoNode* lasso_response_new             (void);

LASSO_EXPORT LassoNode* lasso_response_new_from_export (xmlChar              *buffer,
							lassoNodeExportTypes  export_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_RESPONSE_H__ */
