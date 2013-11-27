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
#include "saml_subject_statement.h"

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="SubjectStatement" type="saml:SubjectStatementAbstractType"/>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoSamlSubjectStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SubjectStatement");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
}

GType
lasso_saml_subject_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlSubjectStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlSubjectStatement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
				"LassoSamlSubjectStatement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_subject_statement_new:
 *
 * Creates a new #LassoSamlSubjectStatement object.
 *
 * Return value: a newly created #LassoSamlSubjectStatement object
 **/
LassoNode*
lasso_saml_subject_statement_new()
{
	return g_object_new(LASSO_TYPE_SAML_SUBJECT_STATEMENT, NULL);
}
