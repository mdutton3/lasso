/* $Id: disco_query_response.h,v 1.5 2005/01/22 15:57:55 $ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2007 Entr'ouvert
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

#ifndef __LASSO_IDWSF2_DISCO_QUERY_RESPONSE_H__
#define __LASSO_IDWSF2_DISCO_QUERY_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
//#include <lasso/xml/disco_credentials.h>
#include <lasso/xml/utility_status.h>

#define LASSO_TYPE_IDWSF2_DISCO_QUERY_RESPONSE (lasso_idwsf2_disco_query_response_get_type())
#define LASSO_IDWSF2_DISCO_QUERY_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_IDWSF2_DISCO_QUERY_RESPONSE, LassoIdwsf2DiscoQueryResponse))
#define LASSO_IDWSF2_DISCO_QUERY_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_IDWSF2_DISCO_QUERY_RESPONSE, LassoIdwsf2DiscoQueryResponseClass))
#define LASSO_IS_IDWSF2_DISCO_QUERY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IDWSF2_DISCO_QUERY_RESPONSE))
#define LASSO_IS_IDWSF2_DISCO_QUERY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_IDWSF2_DISCO_QUERY_RESPONSE))
#define LASSO_IDWSF2_DISCO_QUERY_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IDWSF2_DISCO_QUERY_RESPONSE, \
				    LassoIdwsf2DiscoQueryResponseClass))

typedef struct _LassoIdwsf2DiscoQueryResponse LassoIdwsf2DiscoQueryResponse;
typedef struct _LassoIdwsf2DiscoQueryResponseClass LassoIdwsf2DiscoQueryResponseClass;

struct _LassoIdwsf2DiscoQueryResponse {
	LassoNode parent;

	LassoUtilityStatus *Status;
//	GList *ResourceOffering;
//	LassoIdwsf2DiscoCredentials *Credentials;

	char *id;
};

struct _LassoIdwsf2DiscoQueryResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_query_response_get_type(void);

LASSO_EXPORT LassoIdwsf2DiscoQueryResponse* lasso_idwsf2_disco_query_response_new(LassoUtilityStatus *status);

LASSO_EXPORT LassoIdwsf2DiscoQueryResponse* lasso_idwsf2_disco_query_response_new_from_message(
	const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_QUERY_RESPONSE_H__ */
