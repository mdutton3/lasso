/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/saml_subject_locality.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="SubjectLocality" type="saml:SubjectLocalityType"/>
<complexType name="SubjectLocalityType">
  <attribute name="IPAddress" type="string" use="optional"/>
  <attribute name="DNSAddress" type="string" use="optional"/>
</complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_subject_locality_set_dnsAddress(LassoSamlSubjectLocality *node,
					   const xmlChar *dnsAddress)
{
  g_assert(LASSO_IS_SAML_SUBJECT_LOCALITY(node));
  g_assert(dnsAddress != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "DNSAddress", dnsAddress);
}

void
lasso_saml_subject_locality_set_ipAddress(LassoSamlSubjectLocality *node,
					  const xmlChar *ipAddress)
{
  g_assert(LASSO_IS_SAML_SUBJECT_LOCALITY(node));
  g_assert(ipAddress != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "IPAddress", ipAddress);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_subject_locality_instance_init(LassoSamlSubjectLocality *instance)
{
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, "urn:oasis:names:tc:SAML:1.0:assertion", "saml");
  class->set_name(node, "SubjectLocality");
}

static void
lasso_saml_subject_locality_class_init(LassoSamlSubjectLocalityClass *klass)
{
}

GType lasso_saml_subject_locality_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlSubjectLocalityClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_subject_locality_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlSubjectLocality),
      0,
      (GInstanceInitFunc) lasso_saml_subject_locality_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlSubjectLocality",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_subject_locality_new:
 * 
 * Creates a new <saml:SubjectLocality> node object.
 * 
 * Return value: the new @LassoSamlSubjectLocality
 **/
LassoNode* lasso_saml_subject_locality_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_SUBJECT_LOCALITY, NULL));
}
