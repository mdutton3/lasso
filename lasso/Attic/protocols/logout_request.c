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

#include <lasso/protocols/logout_request.h>
#include <lasso/xml/saml_name_identifier.h>


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_request_instance_init(LassoLogoutRequest *request)
{
}

static void
lasso_logout_request_class_init(LassoLogoutRequestClass *class)
{
}

GType lasso_logout_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLogoutRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_logout_request_class_init,
      NULL,
      NULL,
      sizeof(LassoLogoutRequest),
      0,
      (GInstanceInitFunc) lasso_logout_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_LOGOUT_REQUEST,
				       "LassoLogoutRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_logout_request_new(const xmlChar *providerID,
			 const xmlChar *nameIdentifier,
			 const xmlChar *nameQualifier,
			 const xmlChar *format)
{
  LassoNode *request, *identifier;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_REQUEST, NULL));
  
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
  lasso_lib_logout_request_set_providerID(LASSO_LIB_LOGOUT_REQUEST(request),
					 providerID);

  identifier = lasso_saml_name_identifier_new(nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier),nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier), format);

  lasso_lib_logout_request_set_nameIdentifier(LASSO_LIB_LOGOUT_REQUEST(request), LASSO_SAML_NAME_IDENTIFIER(identifier));

  return (request);
}
