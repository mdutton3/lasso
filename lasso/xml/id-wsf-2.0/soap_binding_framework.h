/* $Id: soap_binding_framework.h 2183 2005-01-22 15:57:56Z $ 
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

#ifndef __LASSO_SOAP_BINDING_FRAMEWORK_H__
#define __LASSO_SOAP_BINDING_FRAMEWORK_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_SOAP_BINDING_FRAMEWORK (lasso_soap_binding_framework_get_type())
#define LASSO_SOAP_BINDING_FRAMEWORK(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	 LASSO_TYPE_SOAP_BINDING_FRAMEWORK, LassoSoapBindingFramework))
#define LASSO_SOAP_BINDING_FRAMEWORK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
	 LASSO_TYPE_SOAP_BINDING_FRAMEWORK, LassoSoapBindingFrameworkClass))
#define LASSO_IS_SOAP_BINDING_FRAMEWORK(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
	 LASSO_TYPE_SOAP_BINDING_FRAMEWORK))
#define LASSO_IS_SOAP_BINDING_FRAMEWORK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
	 LASSO_TYPE_SOAP_BINDING_FRAMEWORK))
#define LASSO_SOAP_BINDING_FRAMEWORK_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
	 LASSO_TYPE_SOAP_BINDING_FRAMEWORK, LassoSoapBindingFrameworkClass)) 

typedef struct _LassoSoapBindingFramework LassoSoapBindingFramework;
typedef struct _LassoSoapBindingFrameworkClass LassoSoapBindingFrameworkClass;

struct _LassoSoapBindingFramework {
	LassoNode parent;

	gchar *Version;
};

struct _LassoSoapBindingFrameworkClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_binding_framework_get_type(void);

LASSO_EXPORT LassoSoapBindingFramework* lasso_soap_binding_framework_new();

LASSO_EXPORT LassoSoapBindingFramework* lasso_soap_binding_framework_new_full(gchar *version);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_BINDING_FRAMEWORK_H__ */
