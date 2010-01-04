/* $Id$
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

#ifndef __LASSO_SOAP_DETAIL_H__
#define __LASSO_SOAP_DETAIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_SOAP_DETAIL (lasso_soap_detail_get_type())
#define LASSO_SOAP_DETAIL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SOAP_DETAIL, LassoSoapDetail))
#define LASSO_SOAP_DETAIL_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SOAP_DETAIL, LassoSoapDetailClass))
#define LASSO_IS_SOAP_DETAIL(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SOAP_DETAIL))
#define LASSO_IS_SOAP_DETAIL_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SOAP_DETAIL))
#define LASSO_SOAP_DETAIL_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SOAP_DETAIL, LassoSoapDetailClass))

typedef struct _LassoSoapDetail LassoSoapDetail;
typedef struct _LassoSoapDetailClass LassoSoapDetailClass;

struct _LassoSoapDetail {
	LassoNode parent;

	GList *any; /* of LassoNode */
};

struct _LassoSoapDetailClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_detail_get_type(void);

LASSO_EXPORT LassoSoapDetail* lasso_soap_detail_new(void);
LASSO_EXPORT LassoSoapDetail* lasso_soap_detail_new_from_message(const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_DETAIL_H__ */
