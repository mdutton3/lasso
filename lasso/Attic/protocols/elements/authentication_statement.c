/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/protocols/elements/authentication_statement.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authentication_statement_instance_init(LassoAuthenticationStatement *authentication_statement)
{
}

static void
lasso_authentication_statement_class_init(LassoAuthenticationStatementClass *class)
{
}

GType lasso_authentication_statement_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthenticationStatementClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authentication_statement_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthenticationStatement),
      0,
      (GInstanceInitFunc) lasso_authentication_statement_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT,
				       "LassoAuthenticationStatement",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authentication_statement_new(const xmlChar *authenticationMethod,
				   const xmlChar *reauthenticateOnOrAfter,
				   xmlChar       *nameIdentifier,
				   const xmlChar *nameQualifier,
				   const xmlChar *format,
				   xmlChar       *idp_nameIdentifier,
				   const xmlChar *idp_nameQualifier,
				   const xmlChar *idp_format)
{
  LassoNode *statement;
  LassoNode *subject, *identifier, *idp_identifier, *subject_confirmation;

  statement = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHENTICATION_STATEMENT, NULL));

  lasso_saml_authentication_statement_set_authenticationMethod(LASSO_SAML_AUTHENTICATION_STATEMENT(statement),
							       authenticationMethod);
  lasso_saml_authentication_statement_set_authenticationInstant(LASSO_SAML_AUTHENTICATION_STATEMENT(statement),
								lasso_get_current_time());
  lasso_lib_authentication_statement_set_reauthenticateOnOrAfter(LASSO_LIB_AUTHENTICATION_STATEMENT(statement),
								 reauthenticateOnOrAfter);

  subject = lasso_lib_subject_new();
  identifier = lasso_saml_name_identifier_new(nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier),
					       nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier),
					format);
  lasso_saml_subject_set_nameIdentifier(LASSO_SAML_SUBJECT(subject),
					LASSO_SAML_NAME_IDENTIFIER(identifier));
  idp_identifier = lasso_lib_idp_provided_name_identifier_new(idp_nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(idp_identifier),
					       idp_nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(idp_identifier),
					idp_format);
  lasso_saml_subject_set_nameIdentifier(LASSO_SAML_SUBJECT(subject),
					LASSO_SAML_NAME_IDENTIFIER(idp_identifier));
  lasso_lib_subject_set_idpProvidedNameIdentifier(LASSO_LIB_SUBJECT(subject),
						  LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idp_identifier));
  subject_confirmation = lasso_saml_subject_confirmation_new();
  lasso_saml_subject_confirmation_set_subjectConfirmationMethod(LASSO_SAML_SUBJECT_CONFIRMATION(subject_confirmation),
								lassoSamlConfirmationMethodBearer);
  lasso_saml_subject_set_subjectConfirmation(LASSO_SAML_SUBJECT(subject),
					     LASSO_SAML_SUBJECT_CONFIRMATION(subject_confirmation));

  lasso_saml_subject_statement_abstract_set_subject(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(statement),
						    LASSO_SAML_SUBJECT(subject));

  return (statement);
}
