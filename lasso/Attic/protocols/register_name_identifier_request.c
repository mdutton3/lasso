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

#include <lasso/protocols/register_name_identifier_request.h>

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_register_name_identifier_request_instance_init(LassoRegisterNameIdentifierRequest *request)
{
}

static void
lasso_register_name_identifier_request_class_init(LassoRegisterNameIdentifierRequestClass *class)
{
}

GType lasso_register_name_identifier_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoRegisterNameIdentifierRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_register_name_identifier_request_class_init,
      NULL,
      NULL,
      sizeof(LassoRegisterNameIdentifierRequest),
      0,
      (GInstanceInitFunc) lasso_register_name_identifier_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST,
				       "LassoRegisterNameIdentifierRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_register_name_identifier_request_new(const xmlChar *providerID,
					   const xmlChar     *idpProvidedNameIdentifier,
					   const xmlChar     *idpNameQualifier,
					   const xmlChar     *idpFormat,
					   const xmlChar     *spProvidedNameIdentifier,
					   const xmlChar     *spNameQualifier,
					   const xmlChar     *spFormat,
					   const xmlChar     *oldProvidedNameIdentifier,
					   const xmlChar     *oldNameQualifier,
					   const xmlChar     *oldFormat)
{
  LassoNode *request, *idpidentifier, *spidentifier, *oldidentifier;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, NULL));
  
  /* Set ONLY required elements/attributs */
  /* RequestID */
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					     (const xmlChar *)lasso_build_unique_id(32));
  /* MajorVersion */
  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						lassoLibMajorVersion);
  /* MinorVersion */
  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						lassoLibMinorVersion);
  /* IssueInstant */
  lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						 lasso_get_current_time());
  /* ProviderID */
  lasso_lib_register_name_identifier_request_set_providerID(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
							    providerID);

  idpidentifier = lasso_lib_idp_provided_name_identifier_new(idpProvidedNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(idpidentifier), idpNameQualifier);
  lasso_node_rename_prop(idpidentifier, "NameQualifier", "IDPNameQualifier");
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(idpidentifier), idpFormat);
  lasso_node_rename_prop(idpidentifier, "Format", "IDPFormat");
  lasso_lib_register_name_identifier_request_set_idpProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									   LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idpidentifier));

  spidentifier = lasso_lib_sp_provided_name_identifier_new(spProvidedNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(spidentifier), spNameQualifier);
  lasso_node_rename_prop(spidentifier, "NameQualifier", "SPNameQualifier");
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(spidentifier), spFormat);
  lasso_node_rename_prop(spidentifier, "Format", "SPFormat");
  lasso_lib_register_name_identifier_request_set_spProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									  LASSO_LIB_SP_PROVIDED_NAME_IDENTIFIER(spidentifier));

  oldidentifier = lasso_lib_old_provided_name_identifier_new(oldProvidedNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(oldidentifier), oldNameQualifier);
  lasso_node_rename_prop(oldidentifier, "NameQualifier", "OldNameQualifier");
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(oldidentifier), oldFormat);
  lasso_node_rename_prop(oldidentifier, "Format", "OldFormat");
  lasso_lib_register_name_identifier_request_set_oldProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									   LASSO_LIB_OLD_PROVIDED_NAME_IDENTIFIER(oldidentifier));

  return (request);
}
