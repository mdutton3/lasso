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
#include "sec_resource_access_statement.h"
#include "./idwsf_strings.h"

/*
 * <xs: element name="ResourceAccessStatement"
 *   type="sec: ResourceAccessStatementType"
 *   substitutionGroup="saml: SubjectStatement"/>
 *
 * <xs: complexType name="ResourceAccessStatementType">
 *   <xs: complexContent>
 *     <xs: extension base="saml: SubjectStatementAbstractType">
 *       <xs: sequence>
 *         <xs: group ref="disco: ResourceIDGroup"/>
 *         <xs: sequence minOccurs="0">
 *           <!-- This is the name of the proxy and it SHOULD carry
 *             SubjectConfirmation information to authorize the
 *             ProxySubject to act on behalf of the
 *             Subject inherited from
 *             SubjectStatementAbstractType -->
 *           <xs: element name="ProxySubject" type="saml: SubjectType"/>
 *           <xs: element ref="sec: SessionContext" minOccurs="0"/>
 *		   </xs: sequence>
 *	     </xs: sequence>
 *     </xs: extension>
 *    </xs: complexContent>
 *   </xs: complexType>
 *
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoSecResourceAccessStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ResourceAccessStatement");
	lasso_node_class_set_ns(nclass, LASSO_SEC_HREF, LASSO_SEC_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_sec_resource_access_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSecResourceAccessStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSecResourceAccessStatement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
				"LassoSecResourceAccessStatement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_sec_resource_access_statement_new:
 *
 * Creates a new #LassoSecResourceAccessStatement object.
 *
 * Return value: a newly created #LassoSecResourceAccessStatement object
 **/
LassoNode* lasso_sec_resource_access_statement_new()
{
	return g_object_new(LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT, NULL);
}
