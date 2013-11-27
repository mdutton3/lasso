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

#include "private.h"
#include "lib_register_name_identifier_response.h"

/**
 * SECTION:lib_register_name_identifier_response
 * @short_description: &lt;lib:RegisterNameIdentifierResponse&gt;
 *
 * <figure><title>Schema fragment for lib:RegisterNameIdentifierResponse</title>
 * <programlisting><![CDATA[
 * <xs:element name="RegisterNameIdentifierResponse" type="StatusResponseType"/>
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
class_init(LassoLibRegisterNameIdentifierResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RegisterNameIdentifierResponse");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
}

GType
lasso_lib_register_name_identifier_response_get_type()
{
	static GType register_name_identifier_response_type = 0;

	if (!register_name_identifier_response_type) {
		static const GTypeInfo register_name_identifier_response_info = {
			sizeof (LassoLibRegisterNameIdentifierResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibRegisterNameIdentifierResponse),
			0,
			NULL,
			NULL,
		};

		register_name_identifier_response_type = g_type_register_static(
				LASSO_TYPE_LIB_STATUS_RESPONSE,
				"LassoLibRegisterNameIdentifierResponse",
				&register_name_identifier_response_info, 0);
	}
	return register_name_identifier_response_type;
}


/**
 * lasso_lib_register_name_identifier_response_new:
 *
 * Creates a new #LassoLibRegisterNameIdentifierResponse object.
 *
 * Return value: a newly created #LassoLibRegisterNameIdentifierResponse object
 **/
LassoNode*
lasso_lib_register_name_identifier_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE, NULL);
}


/**
 * lasso_lib_register_name_identifier_response_new_full:
 * @providerID: the providerID of the responder
 * @statusCodeValue: a response status code
 * @request: the request which is answered by this response
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibRegisterNameIdentifierResponse object and initializes
 * it with the parameters.
 *
 * Return value: a newly created #LassoLibRegisterNameIdentifierResponse object
 **/
LassoNode*
lasso_lib_register_name_identifier_response_new_full(const char *providerID,
		const char *statusCodeValue, LassoLibRegisterNameIdentifierRequest *request,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
{
	LassoLibStatusResponse *response;

	response = g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE, NULL);

	LASSO_LIB_STATUS_RESPONSE(response)->ProviderID = g_strdup(providerID);
	lasso_samlp_response_abstract_fill(
			LASSO_SAMLP_RESPONSE_ABSTRACT(response),
			LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID,
			request->ProviderID);
	LASSO_SAMLP_RESPONSE_ABSTRACT(response)->sign_type = sign_type;
	LASSO_SAMLP_RESPONSE_ABSTRACT(response)->sign_method = sign_method;

	response->RelayState = g_strdup(request->RelayState);
	response->Status = lasso_samlp_status_new();
	response->Status->StatusCode = lasso_samlp_status_code_new();
	response->Status->StatusCode->Value = g_strdup(statusCodeValue);

	return LASSO_NODE(response);
}
