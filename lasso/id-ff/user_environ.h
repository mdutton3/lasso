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

#ifndef __LASSO_USER_ENVIRON_H__
#define __LASSO_USER_ENVIRON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/environs/identity.h>

#define LASSO_TYPE_USER_ENVIRON (lasso_user_environ_get_type())
#define LASSO_USER_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_USER_ENVIRON, LassoUserEnviron))
#define LASSO_USER_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_USER_ENVIRON, LassoUserEnvironClass))
#define LASSO_IS_USER_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_USER_ENVIRON))
#define LASSP_IS_USER_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_USER_ENVIRON))
#define LASSO_USER_ENVIRON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_USER_ENVIRON, LassoUserEnvironClass)) 

typedef struct _LassoUserEnviron LassoUserEnviron;
typedef struct _LassoUserEnvironClass LassoUserEnvironClass;

struct _LassoUserEnviron {
  LassoNode parent;
  
  LassoNode *identities;

  /*< private >*/
};

struct _LassoUserEnvironClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType                lasso_user_environ_get_type(void);
LASSO_EXPORT LassoUserEnviron*    lasso_user_environ_new();

LASSO_EXPORT LassoIdentity *lasso_user_environ_search_identity(LassoUserEnviron *user, char *peer_providerID);
LASSO_EXPORT LassoIdentity *lasso_user_environ_new_identity(LassoUserEnviron *user, char *peer_providerID);

LASSO_EXPORT LassoIdentity *lasso_user_search_by_alias(LassoUserEnviron *user, char *nameIdentifier);
LASSO_EXPORT LassoIdentity *lasso_user_search_by_name(LassoUserEnviron *user, char *nameIdentifier);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_USER_ENVIRON_H__ */
