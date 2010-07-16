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

#include "private.h"
#include "lib_logout_response.h"

/**
 * SECTION:lib_logout_response
 * @short_description: &lt;lib:LogoutResponse&gt;
 *
 * <figure><title>Schema fragment for lib:LogoutResponse</title>
 * <programlisting><![CDATA[
 * <xs:element name="LogoutResponse" type="StatusResponseType"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoLibLogoutResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "LogoutResponse");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
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
			NULL,
			NULL,
		};

		logout_response_type = g_type_register_static(LASSO_TYPE_LIB_STATUS_RESPONSE,
				"LassoLibLogoutResponse", &logout_response_info, 0);
	}
	return logout_response_type;
}

/**
 * lasso_lib_logout_response_new:
 *
 * Creates a new #LassoLibLogoutResponse object.
 *
 * Return value: a newly created #LassoLibLogoutResponse object
 **/
LassoNode*
lasso_lib_logout_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_LOGOUT_RESPONSE, NULL);
}


/**
 * lasso_lib_logout_response_new_full:
 * @providerID: the providerID of the responded
 * @statusCodeValue: a response status code
 * @request: the request this is a response to
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibLogoutResponse object and initializes it with the
 * parameters.
 *
 * Return value: a newly created #LassoLibLogoutResponse object
 **/
LassoNode*
lasso_lib_logout_response_new_full(char *providerID, const char *statusCodeValue,
		LassoLibLogoutRequest *request,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
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
