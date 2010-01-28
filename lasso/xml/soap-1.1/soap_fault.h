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

#ifndef __LASSO_SOAP_FAULT_H__
#define __LASSO_SOAP_FAULT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "./soap_detail.h"

#define LASSO_TYPE_SOAP_FAULT (lasso_soap_fault_get_type())
#define LASSO_SOAP_FAULT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SOAP_FAULT, LassoSoapFault))
#define LASSO_SOAP_FAULT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SOAP_FAULT, LassoSoapFaultClass))
#define LASSO_IS_SOAP_FAULT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SOAP_FAULT))
#define LASSO_IS_SOAP_FAULT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SOAP_FAULT))
#define LASSO_SOAP_FAULT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SOAP_FAULT, LassoSoapFaultClass))

typedef struct _LassoSoapFault LassoSoapFault;
typedef struct _LassoSoapFaultClass LassoSoapFaultClass;

struct _LassoSoapFault {
	LassoNode parent;

	gchar *faultcode;
	gchar *faultstring;
	GList *faultactor; /* of string */
	LassoSoapDetail *Detail;
};

struct _LassoSoapFaultClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_fault_get_type(void);

LASSO_EXPORT LassoSoapFault* lasso_soap_fault_new(void);

LASSO_EXPORT LassoSoapFault* lasso_soap_fault_new_from_message(const gchar *message);

LASSO_EXPORT LassoSoapFault* lasso_soap_fault_new_full(const char *faultcode, const char *faultstring);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_FAULT_H__ */
