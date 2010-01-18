/* $Id: disco_svc_md_association_add.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_H__
#define __LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD \
	(lasso_idwsf2_disco_svc_md_association_add_get_type())
#define LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD, \
		LassoIdWsf2DiscoSvcMDAssociationAdd))
#define LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD, \
		LassoIdWsf2DiscoSvcMDAssociationAddClass))
#define LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD))
#define LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD))
#define LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD, \
		LassoIdWsf2DiscoSvcMDAssociationAddClass))


typedef struct _LassoIdWsf2DiscoSvcMDAssociationAdd LassoIdWsf2DiscoSvcMDAssociationAdd;
typedef struct _LassoIdWsf2DiscoSvcMDAssociationAddClass LassoIdWsf2DiscoSvcMDAssociationAddClass;


struct _LassoIdWsf2DiscoSvcMDAssociationAdd {
	LassoNode parent;

	/*< public >*/
	/* elements */
	GList *SvcMDID; /* of strings */
	/* attributes */
	GHashTable *attributes;
};

struct _LassoIdWsf2DiscoSvcMDAssociationAddClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_svc_md_association_add_get_type(void);
LASSO_EXPORT LassoIdWsf2DiscoSvcMDAssociationAdd*
	lasso_idwsf2_disco_svc_md_association_add_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_H__ */
