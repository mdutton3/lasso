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

#ifndef __LASSO_ENVIRON_H__
#define __LASSO_ENVIRON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/environs/provider.h>

#define LASSO_TYPE_ENVIRON (lasso_environ_get_type())
#define LASSO_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_ENVIRON, LassoEnviron))
#define LASSO_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_ENVIRON, LassoEnvironClass))
#define LASSO_IS_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_ENVIRON))
#define LASSP_IS_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_ENVIRON))
#define LASSO_ENVIRON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_ENVIRON, LassoEnvironClass)) 

typedef enum {
  LassoEnvironTypeGet = 1,
  LassoEnvironTypePost,
  LassoEnvironTypeSoap
} LassoEnvironType;

typedef struct _LassoEnviron LassoEnviron;
typedef struct _LassoEnvironClass LassoEnvironClass;

struct _LassoEnviron {
  GObject parent;
  LassoProvider *local_provider;
  GData *peer_providers;
  LassoNode *request;
  LassoNode *response;
  LassoEnvironType type;
  /*< private >*/
};

struct _LassoEnvironClass {
  GObjectClass parent;
};

LASSO_EXPORT GType lasso_environ_get_type(void);
LASSO_EXPORT LassoEnviron* lasso_environ_new(LassoProvider *local_provider);

LASSO_EXPORT void lasso_environ_add_peer_provider(LassoEnviron *env,
						  const gchar *metadata,
						  const gchar *public_key,
						  const gchar *private_key,
						  const gchar *certificate);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ENVIRON_H__ */
