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

#ifndef __LASSO_SERVER_H__
#define __LASSO_SERVER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/protocols/provider.h>

#define LASSO_TYPE_SERVER (lasso_server_get_type())
#define LASSO_SERVER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SERVER, LassoServer))
#define LASSO_SERVER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SERVER, LassoServerClass))
#define LASSO_IS_SERVER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SERVER))
#define LASSO_IS_SERVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SERVER))
#define LASSO_SERVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SERVER, LassoServerClass)) 

typedef struct _LassoServer LassoServer;
typedef struct _LassoServerClass LassoServerClass;
typedef struct _LassoServerPrivate LassoServerPrivate;

struct _LassoServer {
  LassoProvider parent;

  GPtrArray *providers;
  
  gchar *providerID;   
  gchar *private_key;
  gchar *certificate;
  guint  signature_method;
  /*< private >*/
  LassoServerPrivate *private;
};

struct _LassoServerClass {
  LassoProviderClass parent;
};

LASSO_EXPORT GType          lasso_server_get_type                 (void);

LASSO_EXPORT LassoServer*   lasso_server_new                      (gchar       *metadata,
								   gchar       *public_key,
								   gchar       *private_key,
								   gchar       *certificate,
								   guint       signature_method);

LASSO_EXPORT LassoServer*   lasso_server_new_from_dump            (gchar       *dump);

LASSO_EXPORT gint           lasso_server_add_provider             (LassoServer *server,
								   gchar       *metadata,
								   gchar       *public_key,
								   gchar       *ca_certificate);

LASSO_EXPORT LassoServer*   lasso_server_copy                     (LassoServer *server);

LASSO_EXPORT gchar*         lasso_server_dump                     (LassoServer *server);

LASSO_EXPORT void           lasso_server_destroy                  (LassoServer *server);

LASSO_EXPORT LassoProvider* lasso_server_get_provider             (LassoServer *server,
								   gchar       *providerID);

LASSO_EXPORT gchar*         lasso_server_get_providerID_from_hash (LassoServer *server,
								   gchar *hash);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SERVER_H__ */
