/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
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

#include "../lassomod.h"
#include "py_profile_context.h"

PyObject *profile_context_get_request_type_from_soap_msg(PyObject *self, PyObject *args) {
  gchar *soap_buffer;
  gint   type;

  if (CheckArgs(args, "S:profile_context_get_request_type_from_soap_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "s:profile_context_get_request_type_from_soap_msg",
			 &soap_buffer))
      return NULL;
  }
  else return NULL;

  type = lasso_profile_context_get_request_type_from_soap_msg(soap_buffer);

  return(int_wrap(type));
}

