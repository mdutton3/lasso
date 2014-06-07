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
#include "saml2_subject.h"

/**
 * SECTION:saml2_subject
 * @short_description: &lt;saml2:Subject&gt;
 *
 * <figure><title>Schema fragment for saml2:Subject</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="SubjectType">
 *   <choice>
 *     <sequence>
 *       <choice>
 *         <element ref="saml:BaseID"/>
 *         <element ref="saml:NameID"/>
 *         <element ref="saml:EncryptedID"/>
 *       </choice>
 *       <element ref="saml:SubjectConfirmation" minOccurs="0" maxOccurs="unbounded"/>
 *     </sequence>
 *     <element ref="saml:SubjectConfirmation" maxOccurs="unbounded"/>
 *   </choice>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "BaseID", SNIPPET_NODE | SNIPPET_JUMP_ON_MATCH | SNIPPET_JUMP_3,
		G_STRUCT_OFFSET(LassoSaml2Subject, BaseID), NULL, NULL, NULL},
	{ "NameID", SNIPPET_NODE | SNIPPET_JUMP_ON_MATCH | SNIPPET_JUMP_2,
		G_STRUCT_OFFSET(LassoSaml2Subject, NameID), NULL, NULL, NULL},
	{ "EncryptedID", SNIPPET_NODE | SNIPPET_JUMP_ON_MISS | SNIPPET_JUMP_2,
		G_STRUCT_OFFSET(LassoSaml2Subject, EncryptedID),
		"LassoSaml2EncryptedElement", NULL, NULL},
	{ "SubjectConfirmation", SNIPPET_NODE | SNIPPET_OPTIONAL | SNIPPET_JUMP_ON_MATCH | SNIPPET_JUMP_2,
		G_STRUCT_OFFSET(LassoSaml2Subject, SubjectConfirmation), NULL, NULL, NULL},
	{ "SubjectConfirmation", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSaml2Subject, SubjectConfirmation), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaml2SubjectClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Subject");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml2_subject_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2SubjectClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2Subject),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaml2Subject", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml2_subject_new:
 *
 * Creates a new #LassoSaml2Subject object.
 *
 * Return value: a newly created #LassoSaml2Subject object
 **/
LassoNode*
lasso_saml2_subject_new()
{
	return g_object_new(LASSO_TYPE_SAML2_SUBJECT, NULL);
}
