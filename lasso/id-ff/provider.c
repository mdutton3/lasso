/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
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

#include <lasso/environs/provider.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/
xmlChar *lasso_provider_get_providerID(LassoProvider *provider){
     return(lasso_node_get_attr_value(provider->metadata, "ProviderID"));
}

xmlChar *lasso_provider_get_singleSignOnProtocolProfile(LassoProvider *provider){
     return(lasso_node_get_child_content(provider->metadata, "SingleSignOnProtocolProfile", NULL));
}

xmlChar *lasso_provider_get_singleSignOnServiceUrl(LassoProvider *provider){
     return(lasso_node_get_child_content(provider->metadata, "SingleSignOnServiceUrl", NULL));
}

xmlChar *lasso_provider_get_singleLogoutProtocolProfile(LassoProvider *provider){
     return(lasso_node_get_child_content(provider->metadata, "SingleLogoutProtocolProfile", NULL));
}

xmlChar *lasso_provider_get_singleLogoutServiceUrl(LassoProvider *provider){
     return(lasso_node_get_child_content(provider->metadata, "SingleLogoutServiceUrl", NULL));
}

xmlChar *lasso_provider_get_singleLogoutServiceReturnUrl(LassoProvider *provider){
     return(lasso_node_get_child_content(provider->metadata, "SingleLogoutServiceReturnUrl", NULL));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static xmlChar *lasso_provider_get_direct_child_content(LassoProvider *provider, const xmlChar *name){
     LassoNode *node;

     node = lasso_node_get_child(LASSO_NODE(provider), name, NULL);
     if(!node)
	  return(NULL);
     return(lasso_node_get_content(node));
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_provider_instance_init(LassoProvider *provider)
{
    LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(provider));

    class->set_name(LASSO_NODE(provider), "Provider");
}

static void
lasso_provider_class_init(LassoProviderClass *klass) {
}

GType lasso_provider_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoProviderClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_provider_class_init,
      NULL,
      NULL,
      sizeof(LassoProvider),
      0,
      (GInstanceInitFunc) lasso_provider_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoProvider",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_provider_new(){
     LassoNode *provider;

     provider = LASSO_NODE(g_object_new(LASSO_TYPE_PROVIDER, NULL));

     return (provider);
}

LassoProvider *lasso_provider_new_from_filename(char *filename){
     LassoProvider *provider;
     xmlDocPtr  doc;
     xmlNodePtr root;

     provider = g_object_new(LASSO_TYPE_PROVIDER, NULL);

     /* get root element of doc and duplicate it */
     doc = xmlParseFile(filename);
     root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
     xmlFreeDoc(doc);
     provider->metadata = lasso_node_new_from_xmlNode(root);

     provider->public_key = NULL;
     provider->certificate = NULL;

     return(provider);
}
