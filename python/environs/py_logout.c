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

#include "py_logout.h"

PyObject *LassoLogout_wrap(LassoLogout *logout) {
  PyObject *ret;

  if (logout == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) logout,
                                     (char *) "LassoLogout *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *logout_new(PyObject *self, PyObject *args) {
  PyObject    *server_obj, *user_obj;
  LassoLogout *logout;
  gint         provider_type;

  if (CheckArgs(args, "OOI:logout_new")) {
    if(!PyArg_ParseTuple(args, (char *) "OOi:logout_new",
			 &server_obj, &user_obj, &provider_type))
      return NULL;
  }
  else return NULL;

  logout = lasso_logout_new(LassoServer_get(server_obj),
			    LassoUser_get(user_obj),
			    provider_type);

  return (LassoLogout_wrap(logout));
}

PyObject *logout_build_request_msg(PyObject *self, PyObject *args) {
  PyObject *logout_obj;
  gint      codeError;

  if (CheckArgs(args, "O:logout_build_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:logout_build_request_msg",
			 &logout_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_logout_build_request_msg(LassoLogout_get(logout_obj));

  return(int_wrap(codeError));
}

PyObject *logout_build_response_msg(PyObject *self, PyObject *args) {
  PyObject *logout_obj;
  gint      codeError;

  if (CheckArgs(args, "O:logout_build_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:logout_build_response_msg",
			 &logout_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_logout_build_response_msg(LassoLogout_get(logout_obj));

  return(int_wrap(codeError));
}

PyObject *logout_init_request(PyObject *self, PyObject *args) {
  PyObject *logout_obj;
  gchar    *remote_providerID;
  gint      codeError;

  if (CheckArgs(args, "OS:logout_init_request")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:logout_init_request",
			 &logout_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

  codeError = lasso_logout_init_request(LassoLogout_get(logout_obj), remote_providerID);

  return(int_wrap(codeError));
}

PyObject *logout_process_request_msg(PyObject *self, PyObject *args) {
  PyObject *logout_obj;
  gchar    *request_msg;
  gint      request_method;
  gint      codeError;

  if (CheckArgs(args, "OSI:logout_process_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:logout_process_request_msg",
			 &logout_obj, &request_msg, &request_method))
      return NULL;
  }
  else return NULL;

  codeError = lasso_logout_process_request_msg(LassoLogout_get(logout_obj), request_msg, request_method);

  return(int_wrap(codeError));
}

PyObject *logout_process_response_msg(PyObject *self, PyObject *args) {
  PyObject *logout_obj;
  gchar    *response_msg;
  gint      response_method;
  gint      codeError;

  if (CheckArgs(args, "OSI:logout_process_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:logout_process_response_msg",
			 &logout_obj, &response_msg, &response_method))
      return NULL;
  }
  else return NULL;

  codeError = lasso_logout_process_response_msg(LassoLogout_get(logout_obj), response_msg, response_method);

  return(int_wrap(codeError));
}
