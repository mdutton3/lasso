/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_AUTHN_ENVIRON_H__
#define __LASSO_AUTHN_ENVIRON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/environs/environ.h>

#define LASSO_TYPE_AUTHN_ENVIRON (lasso_authn_environ_get_type())
#define LASSO_AUTHN_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_AUTHN_ENVIRON, LassoAuthnEnviron))
#define LASSO_AUTHN_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_AUTHN_ENVIRON, LassoAuthnEnvironClass))
#define LASSO_IS_AUTHN_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_AUTHN_ENVIRON))
#define LASSO_IS_AUTHN_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_AUTHN_ENVIRON))
#define LASSO_AUTHN_ENVIRON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_AUTHN_ENVIRON, LassoAuthnEnvironClass)) 

typedef struct _LassoAuthnEnviron LassoAuthnEnviron;
typedef struct _LassoAuthnEnvironClass LassoAuthnEnvironClass;

struct _LassoAuthnEnviron {
  LassoEnviron parent;
  /*< private >*/
};

struct _LassoAuthnEnvironClass {
  LassoEnvironClass parent;
};

LASSO_EXPORT GType lasso_authn_environ_get_type(void);
LASSO_EXPORT LassoEnviron* lasso_authn_environ_new(const gchar *metadata,
						   const gchar *public_key,
						   const gchar *private_key,
						   const gchar *certificate);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_AUTHN_ENVIRON_H__ */
