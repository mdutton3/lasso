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

#ifndef __LASSO_SOAP_BINDING_PROVIDER_H__
#define __LASSO_SOAP_BINDING_PROVIDER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_SOAP_BINDING_PROVIDER (lasso_soap_binding_provider_get_type())
#define LASSO_SOAP_BINDING_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SOAP_BINDING_PROVIDER, LassoSoapBindingProvider))
#define LASSO_SOAP_BINDING_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SOAP_BINDING_PROVIDER, LassoSoapBindingProviderClass))
#define LASSO_IS_SOAP_BINDING_PROVIDER(obj) \
			(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SOAP_BINDING_PROVIDER))
#define LASSO_IS_SOAP_BINDING_PROVIDER_CLASS(klass) \
			(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SOAP_BINDING_PROVIDER))
#define LASSO_SOAP_BINDING_PROVIDER_GET_CLASS(o) \
			(G_TYPE_INSTANCE_GET_CLASS ((o), \
			LASSO_TYPE_SOAP_BINDING_PROVIDER, LassoSoapBindingProviderClass))

typedef struct _LassoSoapBindingProvider LassoSoapBindingProvider;
typedef struct _LassoSoapBindingProviderClass LassoSoapBindingProviderClass;

struct _LassoSoapBindingProvider {
	LassoNode parent;

	gchar *providerID;
	gchar *affiliationID;

	gchar *id;
	gchar *mustUnderstand;
	gchar *actor;
};

struct _LassoSoapBindingProviderClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_binding_provider_get_type(void);

LASSO_EXPORT LassoSoapBindingProvider* lasso_soap_binding_provider_new(const gchar *providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_BINDING_PROVIDER_H__ */
