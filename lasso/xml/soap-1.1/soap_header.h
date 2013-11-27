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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_SOAP_HEADER_H__
#define __LASSO_SOAP_HEADER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_SOAP_HEADER (lasso_soap_header_get_type())
#define LASSO_SOAP_HEADER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SOAP_HEADER, LassoSoapHeader))
#define LASSO_SOAP_HEADER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SOAP_HEADER, LassoSoapHeaderClass))
#define LASSO_IS_SOAP_HEADER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SOAP_HEADER))
#define LASSO_IS_SOAP_HEADER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SOAP_HEADER))
#define LASSO_SOAP_HEADER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SOAP_HEADER, LassoSoapHeaderClass))

typedef struct _LassoSoapHeader LassoSoapHeader;
typedef struct _LassoSoapHeaderClass LassoSoapHeaderClass;

struct _LassoSoapHeader {
	LassoNode parent;

	GList *Other; /* of LassoNode */
};

struct _LassoSoapHeaderClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_header_get_type(void);

LASSO_EXPORT LassoSoapHeader* lasso_soap_header_new(void);

LASSO_EXPORT LassoSoapHeader* lasso_soap_header_new_from_message(const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_HEADER_H__ */
