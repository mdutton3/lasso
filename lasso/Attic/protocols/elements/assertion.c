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

#include <lasso/protocols/elements/assertion.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_assertion_instance_init(LassoAssertion *assertion)
{
}

static void
lasso_assertion_class_init(LassoAssertionClass *class)
{
}

GType lasso_assertion_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAssertionClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_assertion_class_init,
      NULL,
      NULL,
      sizeof(LassoAssertion),
      0,
      (GInstanceInitFunc) lasso_assertion_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_ASSERTION,
				       "LassoAssertion",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_assertion_new(const xmlChar *issuer,
		    xmlChar       *requestID)
{
  LassoNode *assertion;
  xmlChar *id, *time;

  g_return_val_if_fail(issuer != NULL, NULL);

  assertion = LASSO_NODE(g_object_new(LASSO_TYPE_ASSERTION, NULL));

  id = lasso_build_unique_id(32);
  lasso_saml_assertion_set_assertionID(LASSO_SAML_ASSERTION(assertion),
				       (const xmlChar *)id);
  xmlFree(id);
  lasso_saml_assertion_set_majorVersion(LASSO_SAML_ASSERTION(assertion),
					lassoLibMajorVersion);
  lasso_saml_assertion_set_minorVersion(LASSO_SAML_ASSERTION(assertion),
					lassoLibMinorVersion);
  time = lasso_get_current_time();
  lasso_saml_assertion_set_issueInstant(LASSO_SAML_ASSERTION(assertion),
					(const xmlChar *)time);
  xmlFree(time);

  lasso_saml_assertion_set_issuer(LASSO_SAML_ASSERTION(assertion), issuer);

  /* InResponseTo */
  if (requestID != NULL) {
    lasso_lib_assertion_set_inResponseTo(LASSO_LIB_ASSERTION(assertion),
					 requestID);
  }

  return (assertion);
}
