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

#include <lasso/environs/identity.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

int lasso_identity_set_local_name_identifier(LassoIdentity *identity, LassoNode *nameIdentifier){
     user->local_nameIdentifier = nameIdentifier;
}

int lasso_identity_set_peer_nameIdentifier(LassoIdentity *identity, LassoNode *nameIdentifier){
     user->peer_nameIdentifier = nameIdentifier;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_identity_instance_init(LassoIdentity *identity){
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(identity));

  class->set_name(LASSO_NODE(identity), "Identity");
}

static void
lasso_identity_class_init(LassoIdentityClass *klass) {
}

GType lasso_identity_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoIdentityClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_identity_class_init,
      NULL,
      NULL,
      sizeof(LassoIdentity),
      0,
      (GInstanceInitFunc) lasso_identity_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoIdentity",
				       &this_info, 0);
  }
  return this_type;
}

LassoIdentity*
lasso_identity_new(char *security_domain)
{
  LassoIdentity *identity;
  LassoNodeClass *class;

  identity = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  class = LASSO_NODE_GET_CLASS(identity);
  class->set_prop(LASSO_NODE(identity), "SecurityDomain", security_domain);
  class->set_prop(LASSO_NODE(identity), "Alias", lasso_build_unique_id(32));

  return(LASSO_IDENTITY(identity));
}

LassoIdentity*
lasso_identity_new_from_name(char *security_domain, char *name)
{
  LassoIdentity *identity;
  LassoNodeClass *class;

  identity = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  class = LASSO_NODE_GET_CLASS(identity);
  class->set_prop(LASSO_NODE(identity), "SecurityDomain", security_domain);
  class->set_prop(LASSO_NODE(identity), "Name", name);

  return(LASSO_IDENTITY(identity));
}
