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
#include "ecp_request.h"

/**
 * SECTION:ecp_request
 * @short_description: &lt;ecp:Request&gt;
 *
 * <figure><title>Schema fragment for ecp:Request</title>
 * <programlisting><![CDATA[
 *
 * <element name="Request" type="ecp:RequestType"/>
 * <complexType name="RequestType">
 *     <sequence>
 *         <element ref="saml:Issuer"/>
 *         <element ref="samlp:IDPList" minOccurs="0"/>
 *     </sequence>
 *     <attribute ref="S:mustUnderstand" use="required"/>
 *     <attribute ref="S:actor" use="required"/>
 *     <attribute name="ProviderName" type="string" use="optional"/>
 *     <attribute name="IsPassive" type="boolean" use="optional"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_ecp_request_validate:
 * @request: the #LassoEcpRequest object to validate
 *
 * Validates the #LassoEcpRequest object conforms to required values.
 *
 * <itemizedlist>
 *   <listitem>mustUnderstand must be TRUE</listitem>
 *   <listitem>actor must be equal to #LASSO_SOAP_ENV_ACTOR</listitem>
 * </itemizedlist>
 *
 * Returns: 0 on success, error code otherwise
 **/
int
lasso_ecp_request_validate(LassoEcpRequest *request)
{
	g_return_val_if_fail(LASSO_IS_ECP_REQUEST(request),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

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
			  G_OBJECT_CLASS_NAME(request),
			  LASSO_SOAP_ENV_ACTOR, request->actor);
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Issuer", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoEcpRequest, Issuer),
		"LassoSaml2NameID", LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "IDPList", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoEcpRequest, IDPList), NULL, LASSO_SAML2_PROTOCOL_PREFIX, LASSO_SAML2_PROTOCOL_HREF},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoEcpRequest, mustUnderstand), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{ "actor", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoEcpRequest, actor), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{ "ProviderName", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoEcpRequest, ProviderName), NULL, NULL, NULL},
	{ "IsPassive", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoEcpRequest, IsPassive), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	lasso_error_t rc = 0;
	LassoEcpRequest *request = LASSO_ECP_REQUEST(node);

	lasso_check_good_rc(parent_class->init_from_xml(node, xmlnode));
	lasso_check_good_rc(lasso_ecp_request_validate(request));

 cleanup:
	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
instance_init(LassoEcpRequest *node)
{
	node->IsPassive = TRUE;
}

static void
class_init(LassoEcpRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "Request");
	lasso_node_class_set_ns(nclass, LASSO_ECP_HREF, LASSO_ECP_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_ecp_request_get_type()
{
	static GType ecp_request_type = 0;

	if (!ecp_request_type) {
		static const GTypeInfo request_info = {
			sizeof (LassoEcpRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoEcpRequest),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		ecp_request_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoEcpRequest", &request_info, 0);
	}
	return ecp_request_type;
}


/**
 * lasso_ecp_request_new:
 * @Issuer:
 * @IsPassive:
 * @ProviderName:
 * @IDPList: (allow-none):
 *
 * Creates and intializes new #LassoEcpRequest object.
 *
 * The #LassoEcpRequest object is initialized as follows:
 * <literallayout>
 *   Issuer = @Issuer
 *   IsPassive = @IsPassive
 *   ProviderName = @ProviderName
 *   IDPList = @IDPList (if non-NULL)
 *   mustUnderstand = TRUE
 *   actor = #LASSO_SOAP_ENV_ACTOR
 * </literallayout>
 *
 * Returns: a newly created and initialized #LassoEcpRequest object
 **/
LassoNode*
lasso_ecp_request_new(const char *Issuer, gboolean IsPassive,
					  const gchar *ProviderName, LassoSamlp2IDPList *IDPList)
{
	LassoEcpRequest *request;

	request = g_object_new(LASSO_TYPE_ECP_REQUEST, NULL);

	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string((char*)Issuer));

	request->IsPassive = IsPassive;
	request->ProviderName = g_strdup(ProviderName);

	if (IDPList) {
		lasso_assign_gobject(request->IDPList, IDPList);
	}
	request->mustUnderstand = TRUE;
	request->actor = g_strdup(LASSO_SOAP_ENV_ACTOR);

	return LASSO_NODE(request);
}
