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
#include "samlp_request.h"

/**
 * SECTION:samlp_request
 * @short_description: &lt;samlp:Request&gt;
 *
 * <figure><title>Schema fragment for samlp:Request</title>
 * <programlisting><![CDATA[
 * <element name="Request" type="samlp:RequestType"/>
 * <complexType name="RequestType">
 *    <complexContent>
 *      <extension base="samlp:RequestAbstractType">
 * 	<choice>
 * 	   <element ref="samlp:Query"/>
 * 	   <element ref="samlp:SubjectQuery"/>
 * 	   <element ref="samlp:AuthenticationQuery"/>
 * 	   <element ref="samlp:AttributeQuery"/>
 * 	   <element ref="samlp:AuthorizationDecisionQuery"/>
 * 	   <element ref="saml:AssertionIDReference" maxOccurs="unbounded"/>
 * 	   <element ref="samlp:AssertionArtifact" maxOccurs="unbounded"/>
 * 	</choice>
 *      </extension>
 *    </complexContent>
 * </complexType>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AssertionArtifact", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSamlpRequest, AssertionArtifact), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlpRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Request");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoSamlpRequest", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_samlp_request_new:
 *
 * Creates a new #LassoSamlpRequest object.
 *
 * Return value: a newly created #LassoSamlpRequest object
 **/
LassoNode*
lasso_samlp_request_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_REQUEST, NULL);
}
