/* $Id: disco_providerid.h 2183 2005-01-22 15:57:56Z dlaniel $ 
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

#ifndef __LASSO_IDWSF2_DISCO_PROVIDERID_H__
#define __LASSO_IDWSF2_DISCO_PROVIDERID_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_IDWSF2_DISCO_PROVIDERID (lasso_idwsf2_disco_providerid_get_type())
#define LASSO_IDWSF2_DISCO_PROVIDERID(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	 LASSO_TYPE_IDWSF2_DISCO_PROVIDERID, LassoIdWsf2DiscoProviderID))
#define LASSO_IDWSF2_DISCO_PROVIDERID_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
	 LASSO_TYPE_IDWSF2_DISCO_PROVIDERID, LassoIdWsf2DiscoProviderIDClass))
#define LASSO_IS_IDWSF2_DISCO_PROVIDERID(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
	 LASSO_TYPE_IDWSF2_DISCO_PROVIDERID))
#define LASSO_IS_IDWSF2_DISCO_PROVIDERID_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
	 LASSO_TYPE_IDWSF2_DISCO_PROVIDERID))
#define LASSO_IDWSF2_DISCO_PROVIDERID_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
	 LASSO_TYPE_IDWSF2_DISCO_PROVIDERID, LassoIdWsf2DiscoProviderIDClass)) 

typedef struct _LassoIdWsf2DiscoProviderID LassoIdWsf2DiscoProviderID;
typedef struct _LassoIdWsf2DiscoProviderIDClass LassoIdWsf2DiscoProviderIDClass;

struct _LassoIdWsf2DiscoProviderID {
	LassoNode parent;

	gchar *content;
};

struct _LassoIdWsf2DiscoProviderIDClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_providerid_get_type(void);

LASSO_EXPORT LassoIdWsf2DiscoProviderID* lasso_idwsf2_disco_providerid_new(void);

LASSO_EXPORT LassoIdWsf2DiscoProviderID*
	lasso_idwsf2_disco_providerid_new_with_content(gchar *content);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_PROVIDERID_H__ */