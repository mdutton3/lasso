/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/protocols/protocol.h>

struct _LassoProtocolPrivate
{
  gboolean  dispose_has_run;
  gchar    *type_name;
};

/*****************************************************************************/
/* virtual public methods                                                    */
/*****************************************************************************/

/*****************************************************************************/
/* virtual private methods                                                   */
/*****************************************************************************/

static void
lasso_node_set_type(LassoProtocol *protocol,
		    const xmlChar *type)
{
  g_return_if_fail(LASSO_IS_PROTOCOL(protocol));

  LassoProtocolClass *class = LASSO_PROTOCOL_GET_CLASS(protocol);
  class->set_type(protocol, type);
}

/*****************************************************************************/
/* implementation methods                                                    */
/*****************************************************************************/

static void
lasso_protocol_impl_set_type(LassoProtocol *protocol,
			     const xmlChar *type)
{
  g_return_if_fail (LASSO_IS_PROTOCOL(protocol));
  g_return_if_fail (type != NULL);

  protocol->private->type_name = xmlStrdup(type);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_protocol_instance_init(LassoProtocol *instance)
{
  LassoProtocol *protocol = LASSO_PROTOCOL(instance);

  protocol->private = g_new (LassoProtocolPrivate, 1);
  protocol->private->dispose_has_run = FALSE;
  protocol->private->type_name = NULL;
}

/* overrided parent class methods */

static void
lasso_protocol_dispose(LassoProtocol *protocol)
{
  if (protocol->private->dispose_has_run) {
    return;
  }
  protocol->private->dispose_has_run = TRUE;

  /* unref reference counted objects */
  /* we don't have any here */
  g_print("%s 0x%x disposed ...\n", protocol->private->type_name, protocol);
}

static void
lasso_protocol_finalize(LassoProtocol *protocol)
{
  g_print("%s 0x%x finalized ...\n", protocol->private->type_name, protocol);
  g_free (protocol->private->type_name);
}

static void
lasso_protocol_class_init(LassoProtocolClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  /* virtual public methods */

  /* virtual private methods */
  class->set_type = lasso_protocol_impl_set_type;

  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_protocol_dispose;
  gobject_class->finalize = (void *)lasso_protocol_finalize;
}

GType lasso_protocol_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoProtocolClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_protocol_class_init,
      NULL,
      NULL,
      sizeof(LassoProtocol),
      0,
      (GInstanceInitFunc) lasso_protocol_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT , "LassoProtocol",
				       &this_info, 0);
  }
  return this_type;
}

LassoProtocol* lasso_protocol_new() {
  return (LASSO_PROTOCOL(g_object_new(LASSO_TYPE_PROTOCOL, NULL)));
}
