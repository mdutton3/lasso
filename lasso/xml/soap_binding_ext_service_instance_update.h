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

#ifndef __LASSO_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE_H__
#define __LASSO_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "soap_binding_ext_credential.h"

#define LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE \
			(lasso_soap_binding_ext_service_instance_update_get_type())
#define LASSO_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			 LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE, \
			 LassoSoapBindingExtServiceInstanceUpdate))
#define LASSO_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE_CLASS(klass) \
			(G_TYPE_CHECK_CLASS_CAST((klass), \
			 LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE, \
			 LassoSoapBindingExtServiceInstanceUpdateClass))
#define LASSO_IS_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE(obj) \
			(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
			 LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE))
#define LASSO_IS_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE_CLASS(klass) \
			(G_TYPE_CHECK_CLASS_TYPE ((klass), \
			 LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE))
#define LASSO_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE_GET_CLASS(o) \
			(G_TYPE_INSTANCE_GET_CLASS ((o), \
			 LASSO_TYPE_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE, \
			 LassoSoapBindingExtServiceInstanceUpdateClass))

typedef struct _LassoSoapBindingExtServiceInstanceUpdate LassoSoapBindingExtServiceInstanceUpdate;
typedef struct _LassoSoapBindingExtServiceInstanceUpdateClass \
			 LassoSoapBindingExtServiceInstanceUpdateClass;

struct _LassoSoapBindingExtServiceInstanceUpdate {
	LassoNode parent;

	gchar *SecurityMechID;
	LassoSoapBindingExtCredential *Credential;
	gchar *Endpoint;

	gchar *id;
	gchar *mustUnderstand;
	gchar *actor;
};

struct _LassoSoapBindingExtServiceInstanceUpdateClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_binding_ext_service_instance_update_get_type(void);

LASSO_EXPORT LassoSoapBindingExtServiceInstanceUpdate* \
	lasso_soap_binding_ext_service_instance_update_new();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_BINDING_EXT_SERVICE_INSTANCE_UPDATE_H__ */
