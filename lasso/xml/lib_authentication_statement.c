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

#include <lasso/xml/lib_authentication_statement.h>

/*
The schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthenticationStatement" type="AuthenticationStatementType" substitutionGroup="saml:Statement"/>
<xs:complexType name="AuthenticationStatementType">
  <xs:complexContent>
    <xs:extension base="saml:AuthenticationStatementType">
      <xs:sequence>
        <xs:element ref="AuthnContext" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute name="ReauthenticateOnOrAfter" type="xs:dateTime" use="optional"/>
      <xs:attribute name="SessionIndex" type="xs:string" use="required"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibAuthenticationStatement *statement = LASSO_LIB_AUTHENTICATION_STATEMENT(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (statement->AuthnContext)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(statement->AuthnContext)));
	if (statement->ReauthenticateOnOrAfter)
		xmlSetProp(xmlnode, "ReauthenticateOnOrAfter", statement->ReauthenticateOnOrAfter);
	if (statement->SessionIndex)
		xmlSetProp(xmlnode, "SessionIndex", statement->SessionIndex);
	
	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibAuthenticationStatement *statement = LASSO_LIB_AUTHENTICATION_STATEMENT(node);
	xmlNode *t;

	parent_class->init_from_xml(node, xmlnode);

	t = xmlnode->children;
	while (t) {
		if (t->type == XML_ELEMENT_NODE && strcmp(t->name, "AuthnContext") == 0) {
			statement->AuthnContext = LASSO_LIB_AUTHN_CONTEXT(
					lasso_node_new_from_xmlNode(t));
			break;
		}
		t = t->next;
	}

	statement->ReauthenticateOnOrAfter = xmlGetProp(xmlnode, "ReauthenticateOnOrAfter");
	statement->SessionIndex = xmlGetProp(xmlnode, "SessionIndex");
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAuthenticationStatement *node)
{
	node->AuthnContext = NULL;
	node->ReauthenticateOnOrAfter = NULL;
	node->SessionIndex = "1"; /* FIXME: proper SessionIndex usage */
}

static void
class_init(LassoLibAuthenticationStatementClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
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
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT,
				"LassoLibAuthenticationStatement", &this_info, 0);
	}
	return this_type;
}

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
	g_return_val_if_fail(sp_identifier || idp_identifier, NULL);

	subject = lasso_lib_subject_new();
	if (sp_identifier == NULL) {
		new_identifier = idp_identifier;
	} else {
		new_identifier = sp_identifier;
	}

	statement = g_object_new(LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT, NULL);
	statement->AuthenticationMethod = g_strdup(authenticationMethod);

	if (authenticationInstant == NULL)
		time = lasso_get_current_time();
	else
		time = g_strdup(authenticationInstant);

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
	subject_confirmation->ConfirmationMethod = LASSO_SAML_CONFIRMATION_METHOD_BEARER;
	LASSO_SAML_SUBJECT(subject)->SubjectConfirmation = subject_confirmation;

	LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(statement)->Subject = LASSO_SAML_SUBJECT(subject);

	return LASSO_LIB_AUTHENTICATION_STATEMENT(statement);
}
