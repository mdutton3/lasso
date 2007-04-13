/* $Id: disco_svc_md_register.h 2428 2005-03-10 08:13:36Z nclapies $
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

#ifndef __LASSO_IDWSF2_DISCO_SVC_MD_REGISTER_H__
#define __LASSO_IDWSF2_DISCO_SVC_MD_REGISTER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER (lasso_idwsf2_disco_svc_md_register_get_type())
#define LASSO_IDWSF2_DISCO_SVC_MD_REGISTER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER, \
				    LassoIdWsf2DiscoSvcMDRegister))
#define LASSO_IDWSF2_DISCO_SVC_MD_REGISTER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER, \
				 LassoIdWsf2DiscoSvcMDRegisterClass))
#define LASSO_IS_IDWSF2_DISCO_SVC_MD_REGISTER(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER))
#define LASSO_IS_IDWSF2_DISCO_SVC_MD_REGISTER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER))
#define LASSO_IDWSF2_DISCO_SVC_MD_REGISTER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER, \
				    LassoIdWsf2DiscoSvcMDRegisterClass)) 

typedef struct _LassoIdWsf2DiscoSvcMDRegister LassoIdWsf2DiscoSvcMDRegister;
typedef struct _LassoIdWsf2DiscoSvcMDRegisterClass LassoIdWsf2DiscoSvcMDRegisterClass;

struct _LassoIdWsf2DiscoSvcMDRegister {
	LassoNode parent;

	/* elements */
	GList *metadata_list;
};

struct _LassoIdWsf2DiscoSvcMDRegisterClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_svc_md_register_get_type(void);

LASSO_EXPORT LassoIdWsf2DiscoSvcMDRegister* lasso_idwsf2_disco_svc_md_register_new(
	gchar *service_type, gchar *abstract, gchar *provider_id);

LASSO_EXPORT LassoIdWsf2DiscoSvcMDRegister*
lasso_idwsf2_disco_svc_md_register_new_from_message(const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_SVC_MD_REGISTER_H__ */
