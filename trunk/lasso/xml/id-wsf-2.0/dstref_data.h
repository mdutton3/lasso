/* $Id: dstref_data.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_DSTREF_DATA_H__
#define __LASSO_IDWSF2_DSTREF_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "dstref_item_data.h"

#define LASSO_TYPE_IDWSF2_DSTREF_DATA (lasso_idwsf2_dstref_data_get_type())
#define LASSO_IDWSF2_DSTREF_DATA(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_DSTREF_DATA, \
		LassoIdWsf2DstRefData))
#define LASSO_IDWSF2_DSTREF_DATA_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_DSTREF_DATA, \
		LassoIdWsf2DstRefDataClass))
#define LASSO_IS_IDWSF2_DSTREF_DATA(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_DSTREF_DATA))
#define LASSO_IS_IDWSF2_DSTREF_DATA_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_DSTREF_DATA))
#define LASSO_IDWSF2_DSTREF_DATA_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_DSTREF_DATA, \
		LassoIdWsf2DstRefDataClass))


typedef struct _LassoIdWsf2DstRefData LassoIdWsf2DstRefData;
typedef struct _LassoIdWsf2DstRefDataClass LassoIdWsf2DstRefDataClass;


struct _LassoIdWsf2DstRefData {
	LassoIdWsf2DstRefItemData parent;

	/*< public >*/
	/* attributes */
	int remaining;
	int nextOffset;
	char *setID;
};


struct _LassoIdWsf2DstRefDataClass {
	LassoIdWsf2DstRefItemDataClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_dstref_data_get_type(void);
LASSO_EXPORT LassoIdWsf2DstRefData* lasso_idwsf2_dstref_data_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DSTREF_DATA_H__ */
