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

#include <lasso/environs/authn_environ.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

char*
lasso_authn_environ_build_request(LassoAuthnEnviron *env) {
  LassoEnviron *e = LASSO_ENVIRON(env);

  e->request = lasso_authn_request_new(lasso_node_get_attr_value(LASSO_NODE(e->local_provider), "ProviderID"));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_environ_instance_init(LassoAuthnEnviron *env)
{
}

static void
lasso_authn_environ_class_init(LassoAuthnEnvironClass *klass)
{
}

GType lasso_authn_environ_get_type()
{
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnEnvironClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_environ_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnEnviron),
      0,
      (GInstanceInitFunc) lasso_authn_environ_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_ENVIRON,
				       "LassoAuthnEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoEnviron* lasso_authn_environ_new(const gchar *metadata,
				      const gchar *public_key,
				      const gchar *private_key,
				      const gchar *certificate)
{
  LassoEnviron *env;
  LassoNode *local_provider;

  env = LASSO_ENVIRON(g_object_new(LASSO_TYPE_AUTHN_ENVIRON, NULL));

  local_provider = lasso_provider_new(metadata);
  lasso_provider_set_public_key(LASSO_PROVIDER(local_provider), public_key);
  lasso_provider_set_private_key(LASSO_PROVIDER(local_provider), private_key);
  lasso_provider_set_certificate(LASSO_PROVIDER(local_provider), certificate);
  env->local_provider = local_provider;

  return LASSO_ENVIRON(g_object_new(LASSO_TYPE_AUTHN_ENVIRON, NULL));
}
