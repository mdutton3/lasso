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

#ifndef __LASSO_SOAP_BODY_H__
#define __LASSO_SOAP_BODY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_SOAP_BODY (lasso_soap_body_get_type())
#define LASSO_SOAP_BODY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SOAP_BODY, LassoSoapBody))
#define LASSO_SOAP_BODY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SOAP_BODY, LassoSoapBodyClass))
#define LASSO_IS_SOAP_BODY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SOAP_BODY))
#define LASSO_IS_SOAP_BODY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SOAP_BODY))
#define LASSO_SOAP_BODY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SOAP_BODY, LassoSoapBodyClass))

typedef struct _LassoSoapBody LassoSoapBody;
typedef struct _LassoSoapBodyClass LassoSoapBodyClass;

struct _LassoSoapBody {
	LassoNode parent;

	GList *any; /* of LassoNode */
	gchar *Id;
	/* TODO : supports of any attributes */
};

struct _LassoSoapBodyClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_body_get_type(void);

LASSO_EXPORT LassoSoapBody* lasso_soap_body_new(void);

LASSO_EXPORT LassoSoapBody* lasso_soap_body_new_from_message(const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_BODY_H__ */
