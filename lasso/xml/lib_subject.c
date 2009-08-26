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
#include "lib_subject.h"

/**
 * SECTION:lib_subject
 * @short_description: &lt;lib:Subject&gt;
 *
 * <figure><title>Schema fragment for lib:Subject</title>
 * <programlisting><![CDATA[
 * <xs:complexType name="SubjectType">
 *   <xs:complexContent>
 *     <xs:extension base="saml:SubjectType">
 *       <xs:sequence>
 *         <xs:element ref="IDPProvidedNameIdentifier"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * <xs:element name="Subject" type="SubjectType" substitutionGroup="saml:Subject"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "IDPProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibSubject, IDPProvidedNameIdentifier), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibSubjectClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Subject");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_subject_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibSubjectClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibSubject),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT,
				"LassoLibSubject", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_subject_new:
 *
 * Creates a new #LassoLibSubject object.
 *
 * Return value: a newly created #LassoLibSubject object
 **/
LassoLibSubject*
lasso_lib_subject_new()
{
	return g_object_new(LASSO_TYPE_LIB_SUBJECT, NULL);
}
