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

#include "errors.h"

#include <lasso/xml/samlp_request_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<complexType name="RequestAbstractType" abstract="true">
  <sequence>
    <element ref="samlp:RespondWith" minOccurs="0" maxOccurs="unbounded"/>
    <element ref="ds:Signature" minOccurs="0"/>
  </sequence>
  <attribute name="RequestID" type="saml:IDType" use="required"/>
  <attribute name="MajorVersion" type="integer" use="required"/>
  <attribute name="MinorVersion" type="integer" use="required"/>
  <attribute name="IssueInstant" type="dateTime" use="required"/>
</complexType>

<element name="RespondWith" type="QName"/>

From oasis-sstc-saml-schema-assertion-1.0.xsd:
<simpleType name="IDType">
  <restriction base="string"/>
</simpleType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_samlp_request_abstract_add_respondWith(LassoSamlpRequestAbstract *node,
					     const xmlChar *respondWith)
{
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(respondWith != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "RespondWith", respondWith, TRUE);
}

void
lasso_samlp_request_abstract_set_issueInstant(LassoSamlpRequestAbstract *node,
					      const xmlChar *issueInstant) {
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(issueInstant != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "IssueInstant", issueInstant);
}

void
lasso_samlp_request_abstract_set_majorVersion(LassoSamlpRequestAbstract *node,
					      const xmlChar *majorVersion) {
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(majorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MajorVersion", majorVersion);
}

void
lasso_samlp_request_abstract_set_minorVersion(LassoSamlpRequestAbstract *node,
					      const xmlChar *minorVersion) {
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(minorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MinorVersion", minorVersion);
}

/**
 * lasso_samlp_request_abstract_impl_set_requestID:
 * @node: the pointer to <Samlp:RequestAbstract/> node
 * @requestID: the RequestID attribute
 * 
 * Sets the RequestID attribute (unique)
 **/
void
lasso_samlp_request_abstract_set_requestID(LassoSamlpRequestAbstract *node,
					   const xmlChar *requestID)
{
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(requestID != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "RequestID", requestID);
}

gint
lasso_samlp_request_abstract_set_signature(LassoSamlpRequestAbstract  *node,
					   gint                        sign_method,
					   const xmlChar              *private_key_file,
					   const xmlChar              *certificate_file,
					   GError                    **err)
{
  gint ret;
  GError *tmp_err = NULL;

  if (err != NULL && *err != NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_ERR_CHECK_FAILED,
		lasso_strerror(LASSO_PARAM_ERROR_ERR_CHECK_FAILED));
    g_return_val_if_fail (err == NULL || *err == NULL,
			  LASSO_PARAM_ERROR_ERR_CHECK_FAILED);
  }
  if (LASSO_IS_SAMLP_REQUEST_ABSTRACT(node) == FALSE) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ,
		lasso_strerror(LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ));
    g_return_val_if_fail(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node),
			 LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ);
  }

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  ret = class->add_signature(LASSO_NODE (node), sign_method,
			     private_key_file, certificate_file, &tmp_err);
  if (ret < 0) {
    g_propagate_error (err, tmp_err);
  }

  return (ret);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_samlp_request_abstract_instance_init(LassoSamlpRequestAbstract *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlProtocolHRef,
		lassoSamlProtocolPrefix);
  class->set_name(LASSO_NODE(node), "RequestAbstract");
}

static void
lasso_samlp_request_abstract_class_init(LassoSamlpRequestAbstractClass *klass)
{
}

GType lasso_samlp_request_abstract_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlpRequestAbstractClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_samlp_request_abstract_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlpRequestAbstract),
      0,
      (GInstanceInitFunc) lasso_samlp_request_abstract_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE ,
				       "LassoSamlpRequestAbstract",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_samlp_request_abstract_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				 NULL));
}
