/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_H__
#define __LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/protocols/name_identifier_mapping_request.h>
#include <lasso/xml/lib_name_identifier_mapping_response.h>

#define LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE (lasso_name_identifier_mapping_response_get_type())
#define LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, LassoNameIdentifierMappingResponse))
#define LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, LassoNameIdentifierMappingResponseClass))
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE))
#define LASSP_IS_NAME_IDENTIFIER_MAPPING_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE))
#define LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, LassoNameIdentifierMappingResponseClass)) 

typedef struct _LassoNameIdentifierMappingResponse LassoNameIdentifierMappingResponse;
typedef struct _LassoNameIdentifierMappingResponseClass LassoNameIdentifierMappingResponseClass;

struct _LassoNameIdentifierMappingResponse {
  LassoLibNameIdentifierMappingResponse parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoNameIdentifierMappingResponseClass {
  LassoLibNameIdentifierMappingResponseClass parent;
};

LASSO_EXPORT GType      lasso_name_identifier_mapping_response_get_type               (void);
LASSO_EXPORT LassoNode* lasso_name_identifier_mapping_response_new                    (const xmlChar *providerID,
										       const xmlChar *statusCodeValue,
										       LassoNode     *request);

LASSO_EXPORT LassoNode *lasso_name_identifier_mapping_response_new_from_dump          (const xmlChar *buffer);
LASSO_EXPORT LassoNode *lasso_name_identifier_mapping_response_new_from_query         (const xmlChar *query);
LASSO_EXPORT LassoNode *lasso_name_identifier_mapping_response_new_from_request_soap  (const xmlChar *buffer,
										       const xmlChar *providerID,
										       const xmlChar *statusCodeValue);
LASSO_EXPORT LassoNode *lasso_name_identifier_mapping_response_new_from_soap          (const xmlChar *buffer);
LASSO_EXPORT LassoNode *lasso_name_identifier_mapping_response_new_from_request_query (const xmlChar *query,
										       const xmlChar *providerID,
										       const xmlChar *statusCodeValue);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_H__ */
