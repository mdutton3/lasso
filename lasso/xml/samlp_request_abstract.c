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
  LassoNodeClass *class;

  if (LASSO_IS_SAMLP_REQUEST_ABSTRACT(node) && respondWith != NULL) {
    class = LASSO_NODE_GET_CLASS(node);
    class->new_child(LASSO_NODE (node), "RespondWith", respondWith, TRUE);
  }
}

void
lasso_samlp_request_abstract_set_issueInstant(LassoSamlpRequestAbstract *node,
					      const xmlChar *issueInstant)
{
  LassoNodeClass *class;

  if (LASSO_IS_SAMLP_REQUEST_ABSTRACT(node) && issueInstant != NULL) {
    class = LASSO_NODE_GET_CLASS(node);
    class->set_prop(LASSO_NODE (node), "IssueInstant", issueInstant);
  }
}

void
lasso_samlp_request_abstract_set_majorVersion(LassoSamlpRequestAbstract *node,
					      const xmlChar *majorVersion)
{
  LassoNodeClass *class;

  if (LASSO_IS_SAMLP_REQUEST_ABSTRACT(node) && majorVersion != NULL) {
    class = LASSO_NODE_GET_CLASS(node);
    class->set_prop(LASSO_NODE (node), "MajorVersion", majorVersion);
  }
}

void
lasso_samlp_request_abstract_set_minorVersion(LassoSamlpRequestAbstract *node,
					      const xmlChar *minorVersion)
{
  LassoNodeClass *class;

  if (LASSO_IS_SAMLP_REQUEST_ABSTRACT(node) && minorVersion != NULL) {
    class = LASSO_NODE_GET_CLASS(node);
    class->set_prop(LASSO_NODE (node), "MinorVersion", minorVersion);
  }
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
  LassoNodeClass *class;

  if (LASSO_IS_SAMLP_REQUEST_ABSTRACT(node) && requestID != NULL) {
    class = LASSO_NODE_GET_CLASS(node);
    class->set_prop(LASSO_NODE (node), "RequestID", requestID);
  }
}

/* obsolete method */
gint
lasso_samlp_request_abstract_set_signature(LassoSamlpRequestAbstract *node,
					   gint                       sign_method,
					   const xmlChar             *private_key_file,
					   const xmlChar             *certificate_file)
{
  gint ret;
  LassoNodeClass *class;

  g_return_val_if_fail(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node),
		       LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ);

  class = LASSO_NODE_GET_CLASS(node);

  ret = class->add_signature(LASSO_NODE (node), sign_method,
			     private_key_file, certificate_file);

  return (ret);
}

gint
lasso_samlp_request_abstract_set_signature_tmpl(LassoSamlpRequestAbstract *node,
						lassoSignatureType         sign_type,
						lassoSignatureMethod       sign_method,
						xmlChar                   *reference_id)
{
  LassoNodeClass *class;

  g_return_val_if_fail(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node),
		       LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ);

  class = LASSO_NODE_GET_CLASS(node);

  return(class->add_signature_tmpl(LASSO_NODE (node), sign_type, sign_method, reference_id));
}

gint
lasso_samlp_request_abstract_sign_signature_tmpl(LassoSamlpRequestAbstract *node,
						 const xmlChar             *private_key_file,
						 const xmlChar             *certificate_file)
{
  LassoNodeClass *class;

  g_return_val_if_fail(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node),
		       LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ);

  class = LASSO_NODE_GET_CLASS(node);

  return(class->sign_signature_tmpl(LASSO_NODE (node), private_key_file,
				    certificate_file));
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
