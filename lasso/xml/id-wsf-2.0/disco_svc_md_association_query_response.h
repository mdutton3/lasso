/* $Id: disco_svc_md_association_query_response.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
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

#ifndef __LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE_H__
#define __LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "util_status.h"

#define LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE \
	(lasso_idwsf2_disco_svc_md_association_query_response_get_type())
#define LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE, \
		LassoIdWsf2DiscoSvcMDAssociationQueryResponse))
#define LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE, \
		LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass))
#define LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE))
#define LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE))
#define LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE, \
		LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass))


typedef struct _LassoIdWsf2DiscoSvcMDAssociationQueryResponse \
	LassoIdWsf2DiscoSvcMDAssociationQueryResponse;
typedef struct _LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass \
	LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass;


struct _LassoIdWsf2DiscoSvcMDAssociationQueryResponse {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoIdWsf2UtilStatus *Status;
	GList *SvcMDID; /* of strings */
	/* attributes */
	GHashTable *attributes;
};


struct _LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_svc_md_association_query_response_get_type(void);
LASSO_EXPORT LassoIdWsf2DiscoSvcMDAssociationQueryResponse*
	lasso_idwsf2_disco_svc_md_association_query_response_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE_H__ */
