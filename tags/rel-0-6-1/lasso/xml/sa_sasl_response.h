/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#ifndef __LASSO_SA_SASL_RESPONSE_H__
#define __LASSO_SA_SASL_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/utility_status.h>
#include <lasso/xml/sa_password_transforms.h>
#include <lasso/xml/xml.h>

#define LASSO_TYPE_SA_SASL_RESPONSE (lasso_sa_sasl_response_get_type())
#define LASSO_SA_SASL_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SA_SASL_RESPONSE, LassoSaSaslResponse))
#define LASSO_SA_SASL_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SA_SASL_RESPONSE, LassoSaSaslResponseClass))
#define LASSO_IS_SA_SASL_RESPONSE(obj) \
			(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SA_SASL_RESPONSE))
#define LASSO_IS_SA_SASL_RESPONSE_CLASS(klass) \
			(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SA_SASL_RESPONSE))
#define LASSO_SA_SASL_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
			LASSO_TYPE_SA_SASL_RESPONSE, LassoSaSaslResponseClass)) 

typedef struct _LassoSaSaslResponse LassoSaSaslResponse;
typedef struct _LassoSaSaslResponseClass LassoSaSaslResponseClass;

struct _LassoSaSaslResponse {
	LassoNode parent;

	/*< public >*/
	LassoUtilityStatus *Status;
	GList *PasswordTransforms;
	GList *Data;
	GList *ResourceOffering;
	GList *Credentials;
	GList *any;

	char *serverMechanism;
	char *id;
};

struct _LassoSaSaslResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_sa_sasl_response_get_type(void);

LASSO_EXPORT LassoSaSaslResponse* lasso_sa_sasl_response_new(LassoUtilityStatus *status);

LASSO_EXPORT LassoSaSaslResponse* lasso_sa_sasl_response_new_from_message(const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SA_SASL_RESPONSE_H__ */
