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

#include "../private.h"
#include "ecp_response.h"

/**
 * SECTION:ecp_response
 * @short_description: &lt;ecp:Response&gt;
 *
 * <figure><title>Schema fragment for ecp:Response</title>
 * <programlisting><![CDATA[
 *
 * <element name="Response" type="ecp:ResponseType"/>
 * <complexType name="ResponseType">
 *     <attribute ref="S:mustUnderstand" use="required"/>
 *     <attribute ref="S:actor" use="required"/>
 *     <attribute name="AssertionConsumerServiceURL" type="anyURI" use="required"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_ecp_response_validate:
 * @response: The #LassoEcpResponse object to validate
 *
 * Validates the #LassoEcpResponse object conforms to required values.
 *
 * <itemizedlist>
 *   <listitem>AssertionConsumerServiceURL must be non-NULL</listitem>
 *   <listitem>mustUnderstand must be TRUE</listitem>
 *   <listitem>actor must be equal to #LASSO_SOAP_ENV_ACTOR</listitem>
 * </itemizedlist>
 *
 * Returns: 0 on success, error code otherwise
 **/
int
lasso_ecp_response_validate(LassoEcpResponse *response)
{
	g_return_val_if_fail(LASSO_IS_ECP_RESPONSE(response),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (response->AssertionConsumerServiceURL == NULL) {
		error("%s.AssertionConsumerServiceURL missing", G_OBJECT_CLASS_NAME(response));
		return LASSO_XML_ERROR_ATTR_NOT_FOUND;
	}

	if (!response->mustUnderstand) {
		error("%s.mustUnderstand must be True", G_OBJECT_CLASS_NAME(response));
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	if (response->actor == NULL) {
		error("%s.actor missing", G_OBJECT_CLASS_NAME(response));
		return LASSO_XML_ERROR_ATTR_NOT_FOUND;
	}

	if (lasso_strisnotequal(response->actor, LASSO_SOAP_ENV_ACTOR)) {
		error("%s.actor invalid, must be \"%s\" not \"%s\"",
			  G_OBJECT_CLASS_NAME(response), LASSO_SOAP_ENV_ACTOR, response->actor);
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AssertionConsumerServiceURL", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoEcpResponse, AssertionConsumerServiceURL), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoEcpResponse, mustUnderstand), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{ "actor", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoEcpResponse, actor), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	lasso_error_t rc = 0;
	LassoEcpResponse *response = LASSO_ECP_RESPONSE(node);

	lasso_check_good_rc(parent_class->init_from_xml(node, xmlnode));
	lasso_check_good_rc(lasso_ecp_response_validate(response));

 cleanup:
	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoEcpResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "Response");
	lasso_node_class_set_ns(nclass, LASSO_ECP_HREF, LASSO_ECP_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_ecp_response_get_type()
{
	static GType ecp_response_type = 0;

	if (!ecp_response_type) {
		static const GTypeInfo response_info = {
			sizeof (LassoEcpResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoEcpResponse),
			0,
			NULL,
			NULL
		};

		ecp_response_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoEcpResponse", &response_info, 0);
	}
	return ecp_response_type;
}


/**
 * lasso_ecp_response_new:
 * @AssertionConsumerServiceURL:  (allow-none):
 *
 * Creates and initializes a new #LassoEcpResponse object.
 *
 * The # object is initialized as follows:
 * <literallayout>
 *   AssertionConsumerServiceURL = @AssertionConsumerServiceURL
 *   mustUnderstand = TRUE
 *   actor = #LASSO_SOAP_ENV_ACTOR
 * </literallayout>
 *
 * Returns: a newly created and initialized #LassoEcpResponse object
 **/
LassoNode*
lasso_ecp_response_new(const gchar *AssertionConsumerServiceURL)
{
	LassoEcpResponse *response;

	response = g_object_new(LASSO_TYPE_ECP_RESPONSE, NULL);

	if (AssertionConsumerServiceURL) {
		response->AssertionConsumerServiceURL = g_strdup(AssertionConsumerServiceURL);
	}

	response->mustUnderstand = TRUE;
	response->actor = g_strdup(LASSO_SOAP_ENV_ACTOR);

	return LASSO_NODE(response);
}
