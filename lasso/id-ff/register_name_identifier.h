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

#ifndef __LASSO_REGISTER_NAME_IDENTIFIER_H__
#define __LASSO_REGISTER_NAME_IDENTIFIER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/environs/profile_context.h>

#include <lasso/protocols/register_name_identifier_request.h>
#include <lasso/protocols/register_name_identifier_response.h>

#define LASSO_TYPE_REGISTER_NAME_IDENTIFIER (lasso_register_name_identifier_get_type())
#define LASSO_REGISTER_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER, LassoRegisterNameIdentifier))
#define LASSO_REGISTER_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER, LassoRegisterNameIdentifierClass))
#define LASSO_IS_REGISTER_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER))
#define LASSP_IS_REGISTER_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER))
#define LASSO_REGISTER_NAME_IDENTIFIER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_REGISTER_NAME_IDENTIFIER, LassoRegisterNameIdentifierClass)) 

typedef struct _LassoRegisterNameIdentifier LassoRegisterNameIdentifier;
typedef struct _LassoRegisterNameIdentifierClass LassoRegisterNameIdentifierClass;

struct _LassoRegisterNameIdentifier {
  LassoProfileContext parent;
  int provider_type;

  /*< private >*/
};

struct _LassoRegisterNameIdentifierClass {
  LassoNodeClass parent;

};

LASSO_EXPORT GType                        lasso_register_name_identifier_get_type           (void);

LASSO_EXPORT LassoRegisterNameIdentifier *lasso_register_name_identifier_new                (LassoServer *server,
											     LassoUser   *user,
											     gint         provider_type);
  
LASSO_EXPORT gint                         lasso_register_name_identifier_build_request_msg  (LassoRegisterNameIdentifier *register_name_identifier);

LASSO_EXPORT gint                         lasso_register_name_identifier_build_response_msg (LassoRegisterNameIdentifier *register_name_identifier);

LASSO_EXPORT gint                         lasso_register_name_identifier_init_request       (LassoRegisterNameIdentifier *register_name_identifier,
											     gchar       *remote_providerID);

LASSO_EXPORT gint                         lasso_register_name_identifier_handle_request     (LassoRegisterNameIdentifier *register_name_identifier,
											     gchar *request_msg,
											     gint request_method);

LASSO_EXPORT gint                         lasso_register_name_identifier_handle_response    (LassoRegisterNameIdentifier *register_name_identifier,
											     gchar *response_msg,
											     gint response_method);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_REGISTER_NAME_IDENTIFIER_H__ */
