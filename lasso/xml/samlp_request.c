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

#include <lasso/xml/samlp_request.h>

/*
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
 * <element name="AssertionArtifact" type="string"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AssertionArtifact", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSamlpRequest, AssertionArtifact) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlpRequest *node)
{
	node->AssertionArtifact = NULL;
}

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
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoSamlpRequest", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_samlp_request_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_REQUEST, NULL);
}

