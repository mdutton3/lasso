/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_H__
#define __LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/samlp_request_abstract.h>
#include <lasso/xml/saml_name_identifier.h>

#define LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST \
	(lasso_lib_name_identifier_mapping_request_get_type())
#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, \
				    LassoLibNameIdentifierMappingRequest))
#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, \
				 LassoLibNameIdentifierMappingRequestClass))
#define LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST))
#define LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST))
#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, \
				    LassoLibNameIdentifierMappingRequestClass)) 

typedef struct _LassoLibNameIdentifierMappingRequest LassoLibNameIdentifierMappingRequest;
typedef struct _LassoLibNameIdentifierMappingRequestClass \
	LassoLibNameIdentifierMappingRequestClass;

struct _LassoLibNameIdentifierMappingRequest {
	LassoSamlpRequestAbstract parent;

	/* <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
	GList *Extension;
	/* <xs:element ref="ProviderID"/> */
	char *ProviderID;
	/* <xs:element ref="saml:NameIdentifier"/> */
	LassoSamlNameIdentifier *NameIdentifier;
	/* <xs:element name="TargetNamespace" type="md:entityIDType"/> */
	char *TargetNamespace;
	/* <xs:attribute ref="consent" use="optional"/> */
	char *consent;
};

struct _LassoLibNameIdentifierMappingRequestClass {
	LassoSamlpRequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_lib_name_identifier_mapping_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_lib_name_identifier_mapping_request_new(void);
LASSO_EXPORT LassoNode* lasso_lib_name_identifier_mapping_request_new_full(
		char *providerID, LassoSamlNameIdentifier *nameIdentifier,
		const char *targetNamespace,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_H__ */
