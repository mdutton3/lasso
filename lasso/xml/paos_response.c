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
#include "paos_response.h"
#include <libxml/tree.h>

/**
 * SECTION:paos_response
 * @short_description: &lt;paos:Response&gt;
 *
 * <figure><title>Schema fragment for paos:Response</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Response" type="ResponseType"/>
 * <xs:complexType name="ResponseType">
 *     <xs:attribute name="refToMessageID" type="IDType" use="optional"/>
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
 * lasso_paos_response_validate:
 * @response: The #LassoPaosResponse object to validate
 *
 * Validates the object conforms to required values.
 *
 * <itemizedlist>
 *   <listitem>mustUnderstand must be TRUE</listitem>
 *   <listitem>actor must be equal to #LASSO_SOAP_ENV_ACTOR</listitem>
 * </itemizedlist>
 *
 * Returns: 0 on success, error code otherwise
 **/
int
lasso_paos_response_validate(LassoPaosResponse *response)
{
	g_return_val_if_fail(LASSO_IS_PAOS_RESPONSE(response),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

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
			  G_OBJECT_CLASS_NAME(response),
			  LASSO_SOAP_ENV_ACTOR, response->actor);
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "refToMessageID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoPaosResponse, refToMessageID), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoPaosResponse, mustUnderstand), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{ "actor", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoPaosResponse, actor), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	lasso_error_t rc = 0;
	LassoPaosResponse *response = LASSO_PAOS_RESPONSE(node);

	lasso_check_good_rc(parent_class->init_from_xml(node, xmlnode));
	lasso_check_good_rc(lasso_paos_response_validate(response));

 cleanup:
	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoPaosResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "Response");
	lasso_node_class_set_ns(nclass, LASSO_PAOS_HREF, LASSO_PAOS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

}

GType
lasso_paos_response_get_type()
{
	static GType paos_response_type = 0;

	if (!paos_response_type) {
		static const GTypeInfo response_info = {
			sizeof (LassoPaosResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoPaosResponse),
			0,
			NULL,
			NULL
		};

		paos_response_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoPaosResponse", &response_info, 0);
	}
	return paos_response_type;
}


/**
 * lasso_paos_response_new:
 * @refToMessageID: (allow-none):
 *
 * The #LassoPaosResponse object is initialized as follows:
 * <literallayout>
 *   refToMessageID = @refToMessageID (if non-NULL)
 *   mustUnderstand = TRUE
 *   actor = #LASSO_SOAP_ENV_ACTOR
 * </literallayout>
 *
 * Return value: a newly created and initialized #LassoPaosResponse object
 **/
LassoNode*
lasso_paos_response_new(const char *refToMessageID)
{
	LassoPaosResponse *response;

	response = g_object_new(LASSO_TYPE_PAOS_RESPONSE, NULL);

	if (refToMessageID) {
		response->refToMessageID = g_strdup(refToMessageID);
	}

	response->mustUnderstand = TRUE;
    response->actor = g_strdup(LASSO_SOAP_ENV_ACTOR);

	return LASSO_NODE(response);
}
