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

#include <lasso/xml/lib_logout_response.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="LogoutResponse" type="StatusResponseType"/>

*/


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "LogoutResponse");

	return xmlnode;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibLogoutResponse *node)
{
}

static void
class_init(LassoLibLogoutResponseClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
#if 0 /* could be used to check QName */
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
#endif
}

GType
lasso_lib_logout_response_get_type()
{
	static GType logout_response_type = 0;

	if (!logout_response_type) {
		static const GTypeInfo logout_response_info = {
			sizeof (LassoLibLogoutResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibLogoutResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		logout_response_type = g_type_register_static(LASSO_TYPE_LIB_STATUS_RESPONSE,
				"LassoLibLogoutResponse", &logout_response_info, 0);
	}
	return logout_response_type;
}

LassoNode*
lasso_lib_logout_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_LOGOUT_RESPONSE, NULL);
}

LassoNode*
lasso_lib_logout_response_new_full(char *providerID, const char *statusCodeValue,
		LassoLibLogoutRequest *request,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoLibStatusResponse *response;

	response = g_object_new(LASSO_TYPE_LIB_LOGOUT_RESPONSE, NULL);
	lasso_samlp_response_abstract_fill(
			LASSO_SAMLP_RESPONSE_ABSTRACT(response),
			LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID,
			request->ProviderID);
	LASSO_SAMLP_RESPONSE_ABSTRACT(response)->sign_type = sign_type;
	LASSO_SAMLP_RESPONSE_ABSTRACT(response)->sign_method = sign_method;

	response->ProviderID = g_strdup(providerID);
	response->RelayState = g_strdup(request->RelayState);
	response->Status = lasso_samlp_status_new();
	response->Status->StatusCode = lasso_samlp_status_code_new();
	response->Status->StatusCode->Value = g_strdup(statusCodeValue);
  
	return LASSO_NODE(response);
}

