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

#ifndef __LASSO_USER_H__
#define __LASSO_USER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/protocols/identity.h>
#include <lasso/protocols/elements/assertion.h>

#define LASSO_TYPE_USER (lasso_user_get_type())
#define LASSO_USER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_USER, LassoUser))
#define LASSO_USER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_USER, LassoUserClass))
#define LASSO_IS_USER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_USER))
#define LASSP_IS_USER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_USER))
#define LASSO_USER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_USER, LassoUserClass)) 

typedef struct _LassoUser LassoUser;
typedef struct _LassoUserClass LassoUserClass;

struct _LassoUser {
  GObject parent;

  /*< public >*/
  GHashTable *assertions;          /* hash for assertions with nameIdentifier as key */
  GHashTable *identities;          /* hash for identities with remote ProviderID as key */

  /*< private >*/
};

struct _LassoUserClass {
  GObjectClass parent;
};

LASSO_EXPORT GType          lasso_user_get_type              (void);
LASSO_EXPORT LassoUser     *lasso_user_new                   (void);
LASSO_EXPORT LassoUser     *lasso_user_new_from_dump         (xmlChar *dump);

LASSO_EXPORT xmlChar       *lasso_user_dump                  (LassoUser *user);

LASSO_EXPORT void           lasso_user_add_assertion         (LassoUser *user,
							      xmlChar   *remote_providerID,
							      LassoNode *assertion);

LASSO_EXPORT LassoNode     *lasso_user_get_assertion         (LassoUser *user,
							      xmlChar   *nameIdentifier);

LASSO_EXPORT void           lasso_user_add_identity          (LassoUser     *user,
							      xmlChar       *remote_providerID,
							      LassoIdentity *identity);

LASSO_EXPORT LassoIdentity *lasso_user_get_identity          (LassoUser *user,
							      xmlChar   *remote_providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_USER_H__ */
