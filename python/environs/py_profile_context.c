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
#include "py_user.h"
#include "py_server.h"

PyObject *LassoProfileContext_wrap(LassoProfileContext *ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
                                     (char *) "LassoProfileContext *", NULL);
  return (ret);
}

/******************************************************************************/

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

/******************************************************************************/

PyObject *profile_context_new(PyObject *self, PyObject *args) {
  PyObject *server_obj, *user_obj;
  LassoProfileContext *ctx;
  LassoUser   *user = NULL;

  if (CheckArgs(args, "Oo:profile_context_new")) {
    if(!PyArg_ParseTuple(args, (char *) "O|O:profile_context_new",
			 &server_obj, &user_obj))
      return NULL;
  }
  else return NULL;

  if (user_obj != Py_None) {
    user = LassoUser_get(user_obj);
  }
  ctx = lasso_profile_context_new(LassoServer_get(server_obj),
				  user);

  return (LassoProfileContext_wrap(ctx));
}

PyObject *profile_context_set_user_from_dump(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  gchar *dump;
  gint   ret;

  if (CheckArgs(args, "OS:profile_context_set_user_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:profile_context_set_user_from_dump",
			 &ctx_obj, &dump))
      return NULL;
  }
  else return NULL;

  ret = lasso_profile_context_set_remote_providerID(LassoProfileContext_get(ctx_obj),
						    dump);

  return(int_wrap(ret));
}
