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

#include <lasso/protocols/authn_request.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_authn_request_set_requestAuthnContext(LassoAuthnRequest *request,
					    GPtrArray         *authnContextClassRefs,
					    GPtrArray         *authnContextStatementRefs,
					    const xmlChar     *authnContextComparison)
{
  g_return_if_fail (LASSO_IS_AUTHN_REQUEST(request));

  LassoNode *request_authn_context;
  gint i;

  /*
    all arguments are optional
    however, we need at least one to create the RequestAuthnContext element
  */
  if (authnContextClassRefs || authnContextStatementRefs || authnContextComparison) {
    /* ok, we create a new RequestAuthnContext instance */
    request_authn_context = lasso_lib_request_authn_context_new();
    /* AuthnContextClassRefs */
    if (authnContextClassRefs != NULL) {
      if (authnContextClassRefs->len > 0) {
	for(i=0; i<authnContextClassRefs->len; i++) {
	  lasso_lib_request_authn_context_add_authnContextClassRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context),
								   lasso_g_ptr_array_index(authnContextClassRefs, i));
	}
      }
    }
    /* AuthnContextStatementRefs */
    if (authnContextStatementRefs != NULL) {
      if (authnContextStatementRefs->len > 0) {
	for(i=0; i<authnContextStatementRefs->len; i++) {
	  lasso_lib_request_authn_context_add_authnContextStatementRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context),
								       lasso_g_ptr_array_index(authnContextStatementRefs, i));
	}
      }
    }
    /* AuthnContextComparison */
    if (authnContextComparison != NULL) {
      lasso_lib_request_authn_context_set_authnContextComparison(LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context),
								 authnContextComparison);
    }
    /* Add RequestAuthnContext in AuthnRequest */
    lasso_lib_authn_request_set_requestAuthnContext(LASSO_LIB_AUTHN_REQUEST(request),
						    LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context));
  }
}

void
lasso_authn_request_set_scoping(LassoAuthnRequest *request,
				gint               proxyCount)
{
  g_return_if_fail (LASSO_IS_AUTHN_REQUEST(request));

  LassoNode *scoping;

  /* create a new Scoping instance */
  scoping = lasso_lib_scoping_new();
  /* ProxyCount */
  lasso_lib_scoping_set_proxyCount(LASSO_LIB_SCOPING(scoping), proxyCount);
  /* FIXME : set IDPList here */
  lasso_lib_authn_request_set_scoping(LASSO_LIB_AUTHN_REQUEST(request),
				      LASSO_LIB_SCOPING(scoping));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_request_instance_init(LassoAuthnRequest *request)
{
}

static void
lasso_authn_request_class_init(LassoAuthnRequestClass *class)
{
}

GType lasso_authn_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_request_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnRequest),
      0,
      (GInstanceInitFunc) lasso_authn_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHN_REQUEST,
				       "LassoAuthnRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authn_request_new(const xmlChar *providerID)
{
  LassoNode *request;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_REQUEST, NULL));
  
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
  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request),
					 providerID);
  
  return (request);
}
