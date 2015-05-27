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
#include "paos_request.h"
#include <libxml/tree.h>

/**
 * SECTION:paos_request
 * @short_description: &lt;paos:Request&gt;
 *
 * <figure><title>Schema fragment for paos:Request</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Request" type="RequestType"/>
 * <xs:complexType name="RequestType">
 *     <xs:attribute name="responseConsumerURL" type="xs:anyURI" use="required"/>
 *     <xs:attribute name="service" type="xs:anyURI" use="required"/>
 *     <xs:attribute name="messageID" type="IDType" use="optional"/>
 *     <xs:attribute ref="S:mustUnderstand" use="required"/>
 *     <xs:attribute ref="S:actor" use="required"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_paos_request_validate:
 * @request: The #LassoPaosRequest object to validate
 *
 * Validates the object conforms to required values.
 *
 * <itemizedlist>
 *   <listitem>responseConsumerURL must be non-NULL</listitem>
 *   <listitem>mustUnderstand must be TRUE</listitem>
 *   <listitem>actor must be equal to #LASSO_SOAP_ENV_ACTOR</listitem>
 *   <listitem>service must be equal to #LASSO_ECP_HREF</listitem>
 * </itemizedlist>
 *
 * Returns: 0 on success, error code otherwise
 **/
int
lasso_paos_request_validate(LassoPaosRequest *request)
{
	g_return_val_if_fail(LASSO_IS_PAOS_REQUEST(request),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (request->responseConsumerURL == NULL) {
		error("%s.responseConsumerURL missing", G_OBJECT_CLASS_NAME(request));
		return LASSO_XML_ERROR_ATTR_NOT_FOUND;
	}

	if (request->service == NULL) {
		error("%s.service missing", G_OBJECT_CLASS_NAME(request));
		return LASSO_XML_ERROR_ATTR_NOT_FOUND;
	}

	if (lasso_strisnotequal(request->service, LASSO_ECP_HREF)) {
		error("%s.service invalid, must be \"%s\" not \"%s\"",
			  G_OBJECT_CLASS_NAME(request), LASSO_ECP_HREF, request->service);
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	if (!request->mustUnderstand) {
		error("%s.mustUnderstand must be True", G_OBJECT_CLASS_NAME(request));
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	if (request->actor == NULL) {
		error("%s.actor missing", G_OBJECT_CLASS_NAME(request));
		return LASSO_XML_ERROR_ATTR_NOT_FOUND;
	}

	if (lasso_strisnotequal(request->actor, LASSO_SOAP_ENV_ACTOR)) {
		error("%s.actor invalid, must be \"%s\" not \"%s\"",
			  G_OBJECT_CLASS_NAME(request), LASSO_SOAP_ENV_ACTOR, request->actor);
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "responseConsumerURL", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoPaosRequest, responseConsumerURL), NULL, NULL, NULL},
	{ "service", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoPaosRequest, service), NULL, NULL, NULL},
	{ "messageID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoPaosRequest, messageID), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoPaosRequest, mustUnderstand), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{ "actor", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoPaosRequest, actor), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	lasso_error_t rc = 0;
	LassoPaosRequest *request = LASSO_PAOS_REQUEST(node);

	lasso_check_good_rc(parent_class->init_from_xml(node, xmlnode));
	lasso_check_good_rc(lasso_paos_request_validate(request));

 cleanup:
	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoPaosRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "Request");
	lasso_node_class_set_ns(nclass, LASSO_PAOS_HREF, LASSO_PAOS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

}

GType
lasso_paos_request_get_type()
{
	static GType paos_request_type = 0;

	if (!paos_request_type) {
		static const GTypeInfo request_info = {
			sizeof (LassoPaosRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoPaosRequest),
			0,
			NULL,
			NULL
		};

		paos_request_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoPaosRequest", &request_info, 0);
	}
	return paos_request_type;
}


/**
 * lasso_paos_request_new:
 * @responseConsumerURL: (allow-none):
 * @messageID: (allow-none):
 *
 * The #LassoPaosRequest object is initialized as follows:
 * <literallayout>
 *   responseConsumerURL = @responseConsumerURL (if non-NULL)
 *   messageID = @messageID (if non-NULL) otherwise generated unique id
 *   mustUnderstand = TRUE
 *   actor = #LASSO_SOAP_ENV_ACTOR
 *   service = #LASSO_ECP_HREF
 * </literallayout>
 *
 * Returns: newly created & initialized #LassoPaosRequest object
 **/
LassoNode*
lasso_paos_request_new(const gchar *responseConsumerURL, const gchar *messageID)
{
	LassoPaosRequest *request;

	request = g_object_new(LASSO_TYPE_PAOS_REQUEST, NULL);

	if (responseConsumerURL) {
		request->responseConsumerURL = g_strdup(responseConsumerURL);
	}

	if (messageID) {
		request->messageID = g_strdup(messageID);
	} else {
		request->messageID = lasso_build_unique_id(32);
	}

	request->mustUnderstand = TRUE;
    request->actor = g_strdup(LASSO_SOAP_ENV_ACTOR);
	request->service = g_strdup(LASSO_ECP_HREF);

	return LASSO_NODE(request);
}
