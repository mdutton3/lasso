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
#include "ecp_relaystate.h"

/**
 * SECTION:ecp_relaystate
 * @short_description: &lt;ecp:RelayState&gt;
 *
 * <figure><title>Schema fragment for ecp:RelayState</title>
 * <programlisting><![CDATA[
 *
 * <element name="RelayState" type="ecp:RelayStateType"/>
 * <complexType name="RelayStateType">
 *     <simpleContent>
 *         <extension base="string">
 *             <attribute ref="S:mustUnderstand" use="required"/>
 *             <attribute ref="S:actor" use="required"/>
 *         </extension>
 *     </simpleContent>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_ecp_relay_state_validate:
 * @relaystate: The #LassoEcpRelayState
 *
 * Validates the #LassoEcpRelayState object conforms to required values.
 *
 * <itemizedlist>
 *   <listitem>RelayState must be non-NULL</listitem>
 *   <listitem>mustUnderstand must be TRUE</listitem>
 *   <listitem>actor must be equal to #LASSO_SOAP_ENV_ACTOR</listitem>
 * </itemizedlist>
 *
 * Returns: 0 on success, error code otherwise
 **/
int
lasso_ecp_relay_state_validate(LassoEcpRelayState *relaystate)
{
	g_return_val_if_fail(LASSO_IS_ECP_RELAYSTATE(relaystate),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (relaystate->RelayState == NULL) {
		error("%s.RelayState missing", G_OBJECT_CLASS_NAME(relaystate));
		return LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
	}

	if (!relaystate->mustUnderstand) {
		error("%s.mustUnderstand must be True", G_OBJECT_CLASS_NAME(relaystate));
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	if (relaystate->actor == NULL) {
		error("%s.actor missing", G_OBJECT_CLASS_NAME(relaystate));
		return LASSO_XML_ERROR_ATTR_NOT_FOUND;
	}

	if (lasso_strisnotequal(relaystate->actor, LASSO_SOAP_ENV_ACTOR)) {
		error("%s.actor invalid, must be \"%s\" not \"%s\"",
			  G_OBJECT_CLASS_NAME(relaystate),
			  LASSO_SOAP_ENV_ACTOR, relaystate->actor);
		return LASSO_XML_ERROR_ATTR_VALUE_INVALID;
	}

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "RelayState", SNIPPET_TEXT_CHILD, G_STRUCT_OFFSET(LassoEcpRelayState, RelayState), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoEcpRelayState, mustUnderstand), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{ "actor", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoEcpRelayState, actor), NULL, LASSO_SOAP_ENV_PREFIX, LASSO_SOAP_ENV_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	lasso_error_t rc = 0;
	LassoEcpRelayState *relaystate = LASSO_ECP_RELAYSTATE(node);

	lasso_check_good_rc(parent_class->init_from_xml(node, xmlnode));
	lasso_check_good_rc(lasso_ecp_relay_state_validate(relaystate));

 cleanup:
	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoEcpRelayStateClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "RelayState");
	lasso_node_class_set_ns(nclass, LASSO_ECP_HREF, LASSO_ECP_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_ecp_relay_state_get_type()
{
	static GType ecp_relay_state_type = 0;

	if (!ecp_relay_state_type) {
		static const GTypeInfo relaystate_info = {
			sizeof (LassoEcpRelayStateClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoEcpRelayState),
			0,
			NULL,
			NULL
		};

		ecp_relay_state_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoEcpRelayState", &relaystate_info, 0);
	}
	return ecp_relay_state_type;
}


/**
 * lasso_ecp_relay_state_new:
 * @RelayState: (allow-none):
 *
 *
 * The #LassoEcpRelayState object is initialized as follows:
 * <literallayout>
 *   RelayState = @RelayState (if non-NULL)
 *   mustUnderstand = TRUE
 *   actor = #LASSO_SOAP_ENV_ACTOR
 * </literallayout>
 *
 * Returns: a newly created and initialized #LassoEcpRelayState object
 **/
LassoNode*
lasso_ecp_relay_state_new(const gchar *RelayState)
{
	LassoEcpRelayState *relaystate;

	relaystate = g_object_new(LASSO_TYPE_ECP_RELAYSTATE, NULL);

	if (RelayState) {
		relaystate->RelayState = g_strdup(RelayState);
	}

	relaystate->mustUnderstand = TRUE;
    relaystate->actor = g_strdup(LASSO_SOAP_ENV_ACTOR);

	return LASSO_NODE(relaystate);
}
