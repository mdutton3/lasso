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

void
lasso_provider_set_public_key(LassoProvider *provider,
			      const gchar *key)
{
  g_return_if_fail(key != NULL);
  
  provider->public_key = g_strdup(key);
}

void
lasso_provider_set_private_key(LassoProvider *provider,
			       const gchar *key)
{
  g_return_if_fail(key != NULL);
  
  provider->private_key = g_strdup(key);
}

void
lasso_provider_set_certificate(LassoProvider *provider,
			       const gchar *certificate)
{
  g_return_if_fail(certificate != NULL);
  
  provider->certificate = g_strdup(certificate);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_provider_instance_init(LassoProvider *provider)
{
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

LassoNode* lasso_provider_new(const gchar *metadata_file) {
  LassoNode *provider;
  xmlDocPtr  doc = xmlParseFile(metadata_file);
  xmlNodePtr root;

  provider = LASSO_NODE(g_object_new(LASSO_TYPE_PROVIDER, NULL));

  /* get root element of doc and duplicate it */
  root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
  /* free doc */
  xmlFreeDoc(doc);
  LASSO_NODE_GET_CLASS(provider)->set_xmlNode(provider, root);

  return (provider);
}
