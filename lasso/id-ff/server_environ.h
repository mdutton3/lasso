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

#ifndef __LASSO_SERVER_ENVIRON_H__
#define __LASSO_SERVER_ENVIRON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/environs/provider.h>

#define LASSO_TYPE_SERVER_ENVIRON (lasso_server_environ_get_type())
#define LASSO_SERVER_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SERVER_ENVIRON, LassoServerEnviron))
#define LASSO_SERVER_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SERVER_ENVIRON, LassoServerEnvironClass))
#define LASSO_IS_SERVER_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SERVER_ENVIRON))
#define LASSP_IS_SERVER_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SERVER_ENVIRON))
#define LASSO_SERVER_ENVIRON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SERVER_ENVIRON, LassoServerEnvironClass)) 

typedef struct _LassoServerEnviron LassoServerEnviron;
typedef struct _LassoServerEnvironClass LassoServerEnvironClass;

struct _LassoServerEnviron {
  GObject parent;

  GPtrArray *providers;

  char *private_key;
  char *public_key;
  char *certificate;

  /*< private >*/
};

struct _LassoServerEnvironClass {
  GObjectClass parent;
};

LASSO_EXPORT GType               lasso_server_environ_get_type               (void);
LASSO_EXPORT LassoServerEnviron *lasso_server_environ_new                    (void);

LASSO_EXPORT int                 lasso_server_environ_add_provider_from_file (LassoServerEnviron *server, char *filename);
LASSO_EXPORT LassoProvider      *lasso_server_environ_get_provider           (LassoServerEnviron *server, char *providerID);

LASSO_EXPORT int                 lasso_server_environ_set_security           (char *private_key, char *public_key, char *certificate);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SERVER_ENVIRON_H__ */
