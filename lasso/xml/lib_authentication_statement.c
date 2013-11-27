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
#include "lib_authentication_statement.h"
#include "lib_subject.h"

/**
 * SECTION:lib_authentication_statement
 * @short_description: &lt;lib:AuthenticationStatement&gt;
 *
 * <figure><title>Schema fragment for lib:AuthenticationStatement</title>
 * <programlisting><![CDATA[
 * <xs:element name="AuthenticationStatement" type="AuthenticationStatementType"
 *   substitutionGroup="saml:Statement"/>
 * <xs:complexType name="AuthenticationStatementType">
 *   <xs:complexContent>
 *     <xs:extension base="saml:AuthenticationStatementType">
 *       <xs:sequence>
 *         <xs:element ref="AuthnContext" minOccurs="0"/>
 *       </xs:sequence>
 *       <xs:attribute name="ReauthenticateOnOrAfter" type="xs:dateTime" use="optional"/>
 *       <xs:attribute name="SessionIndex" type="xs:string" use="required"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AuthnContext", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibAuthenticationStatement, AuthnContext), NULL, NULL, NULL},
	{ "ReauthenticateOnOrAfter", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibAuthenticationStatement, ReauthenticateOnOrAfter), NULL, NULL, NULL},
	{ "SessionIndex", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibAuthenticationStatement, SessionIndex), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibAuthenticationStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->node_data->xsi_sub_type = TRUE;
	lasso_node_class_set_nodename(nclass, "AuthenticationStatementType");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_authentication_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthenticationStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthenticationStatement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT,
				"LassoLibAuthenticationStatement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_authentication_statement_new:
 *
 * Creates a new #LassoLibAuthenticationStatement object.
 *
 * Return value: a newly created #LassoLibAuthenticationStatement object
 **/
LassoLibAuthenticationStatement*
lasso_lib_authentication_statement_new(void)
{
	return g_object_new(LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT, NULL);
}

/**
 * lasso_lib_authentication_statement_new_full:
 * @authenticationMethod: an URI identifier for the authentication method
 * @authenticationInstant:(allow-none): an ISO-8601 formatted timestamp for the authentication
 * instant
 * @reauthenticateOnOrAfter:(allow-none): an ISO-8601 formatted timestamp to set a limit on the value of this
 * authentication
 * @sp_identifier:(allow-none) a #LassoSamlNameIdentifier object, the SP qualifier for the subject of this statement
 * @idp_identifier: a #LassoSamlNameIdentifier object, the IdP qualifier for the subject of this statemtn
 *
 * Creates a new #LassoLibAuthenticationStatement object and initializes its subject,
 * its AuthenticationMethod, its AuthenticationInstant, 
 *
 * Return value: a newly created #LassoLibAuthenticationStatement object
 **/
LassoLibAuthenticationStatement*
lasso_lib_authentication_statement_new_full(const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		LassoSamlNameIdentifier *sp_identifier,
		LassoSamlNameIdentifier *idp_identifier)
{
	LassoSamlAuthenticationStatement *statement;
	LassoSamlNameIdentifier *new_identifier, *new_idp_identifier;
	LassoLibSubject *subject;
	LassoSamlSubjectConfirmation *subject_confirmation;
	char *time;

	g_return_val_if_fail(LASSO_IS_SAML_NAME_IDENTIFIER(idp_identifier), NULL);
	g_return_val_if_fail(authenticationMethod, NULL);

	subject = lasso_lib_subject_new();
	if (sp_identifier == NULL) {
		new_identifier = idp_identifier;
	} else {
		new_identifier = sp_identifier;
	}

	statement = g_object_new(LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT, NULL);
	statement->AuthenticationMethod = g_strdup(authenticationMethod);

	if (authenticationInstant == NULL) {
		time = lasso_get_current_time();
	} else {
		time = g_strdup(authenticationInstant);
	}

	statement->AuthenticationInstant = time;

	LASSO_LIB_AUTHENTICATION_STATEMENT(statement)->ReauthenticateOnOrAfter =
		g_strdup(reauthenticateOnOrAfter);

	LASSO_SAML_SUBJECT(subject)->NameIdentifier = g_object_ref(new_identifier);

	if (sp_identifier != NULL) {
		/* create a new IdpProvidedNameIdentifier and use idp_identifier data to fill it */
		new_idp_identifier = lasso_saml_name_identifier_new();
		new_idp_identifier->content = g_strdup(idp_identifier->content);
		new_idp_identifier->NameQualifier = g_strdup(idp_identifier->NameQualifier);
		new_idp_identifier->Format = g_strdup(idp_identifier->Format);
		subject->IDPProvidedNameIdentifier = new_idp_identifier;
	}

	/* SubjectConfirmation & Subject */
	subject_confirmation = lasso_saml_subject_confirmation_new();
	subject_confirmation->ConfirmationMethod = NULL;
	LASSO_SAML_SUBJECT(subject)->SubjectConfirmation = subject_confirmation;

	LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(statement)->Subject = LASSO_SAML_SUBJECT(subject);

	return LASSO_LIB_AUTHENTICATION_STATEMENT(statement);
}
