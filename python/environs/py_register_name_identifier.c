/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
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

#include "../lassomod.h"

#include "py_register_name_identifier.h"

PyObject *LassoRegisterNameIdentifier_wrap(LassoRegisterNameIdentifier *register_name_identifier) {
  PyObject *ret;

  if (register_name_identifier == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) register_name_identifier,
                                     (char *) "LassoRegisterNameIdentifier *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *register_name_identifier_getattr(PyObject *self, PyObject *args) {
  PyObject *register_name_identifier_obj;
  LassoRegisterNameIdentifier *register_name_identifier;
  const char *attr;

  if (CheckArgs(args, "OS:register_name_identifier_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:register_name_identifier_get_attr", &register_name_identifier_obj, &attr))
      return NULL;
  }
  else return NULL;

  register_name_identifier = LassoRegisterNameIdentifier_get(register_name_identifier_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssss]", "identity", "msg_url", "msg_body",
			 "msg_relayState");
  if (!strcmp(attr, "identity"))
    return (LassoIdentity_wrap(LASSO_PROFILE(register_name_identifier)->identity));
  if (!strcmp(attr, "msg_url"))
    return (charPtrConst_wrap(LASSO_PROFILE(register_name_identifier)->msg_url));
  if (!strcmp(attr, "msg_body"))
    return (charPtrConst_wrap(LASSO_PROFILE(register_name_identifier)->msg_body));
  if (!strcmp(attr, "msg_relayState"))
    return (charPtrConst_wrap(LASSO_PROFILE(register_name_identifier)->msg_relayState));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *register_name_identifier_new(PyObject *self, PyObject *args) {
  PyObject    *server_obj;
  LassoRegisterNameIdentifier *register_name_identifier;
  gint         provider_type;

  if (CheckArgs(args, "OI:register_name_identifier_new")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:register_name_identifier_new",
			 &server_obj, &provider_type))
      return NULL;
  }
  else return NULL;

  register_name_identifier = lasso_register_name_identifier_new(LassoServer_get(server_obj),
								provider_type);

  return (LassoRegisterNameIdentifier_wrap(register_name_identifier));
}


PyObject *register_name_identifier_build_request_msg(PyObject *self, PyObject *args) {
  PyObject *register_name_identifier_obj;
  gint      codeError;

  if (CheckArgs(args, "O:register_name_identifier_build_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:register_name_identifier_build_request_msg",
			 &register_name_identifier_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_register_name_identifier_build_request_msg(LassoRegisterNameIdentifier_get(register_name_identifier_obj));

  return(int_wrap(codeError));
}

PyObject *register_name_identifier_build_response_msg(PyObject *self, PyObject *args) {
  PyObject *register_name_identifier_obj;
  gint      codeError;

  if (CheckArgs(args, "O:register_name_identifier_build_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:register_name_identifier_build_response_msg",
			 &register_name_identifier_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_register_name_identifier_build_response_msg(LassoRegisterNameIdentifier_get(register_name_identifier_obj));

  return(int_wrap(codeError));
}

PyObject *register_name_identifier_destroy(PyObject *self, PyObject *args){
  PyObject *register_name_identifier_obj;

  if (CheckArgs(args, "O:register_name_identifier_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:register_name_identifier_destroy",
			 &register_name_identifier_obj))
      return NULL;
  }
  else return NULL;

  lasso_register_name_identifier_destroy(LassoRegisterNameIdentifier_get(register_name_identifier_obj));

  Py_INCREF(Py_None);
  return(Py_None);
}

PyObject *register_name_identifier_init_request(PyObject *self, PyObject *args) {
  PyObject *register_name_identifier_obj;
  gchar    *remote_providerID;
  gint      codeError;

  if (CheckArgs(args, "OS:register_name_identifier_init_request")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:register_name_identifier_init_request",
			 &register_name_identifier_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

  codeError = lasso_register_name_identifier_init_request(LassoRegisterNameIdentifier_get(register_name_identifier_obj),
							  remote_providerID);

  return(int_wrap(codeError));
}

PyObject *register_name_identifier_process_request_msg(PyObject *self, PyObject *args) {
  PyObject *register_name_identifier_obj;
  gchar    *request_msg;
  gint      request_method;
  gint      codeError;

  if (CheckArgs(args, "OS:register_name_identifier_process_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "OS:register_name_identifier_process_request_msg",
			 &register_name_identifier_obj, &request_msg, &request_method))
      return NULL;
  }
  else return NULL;

  codeError = lasso_register_name_identifier_process_request_msg(LassoRegisterNameIdentifier_get(register_name_identifier_obj),
								 request_msg,
								 request_method);

  return(int_wrap(codeError));
}

PyObject *register_name_identifier_process_response_msg(PyObject *self, PyObject *args) {
  PyObject *register_name_identifier_obj;
  gchar    *response_msg;
  gint      response_method;
  gint      codeError;

  if (CheckArgs(args, "OSI:register_name_identifier_process_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:register_name_identifier_process_response_msg",
			 &register_name_identifier_obj, &response_msg, &response_method))
      return NULL;
  }
  else return NULL;

  codeError = lasso_register_name_identifier_process_response_msg(LassoRegisterNameIdentifier_get(register_name_identifier_obj),
								  response_msg, response_method);

  return(int_wrap(codeError));
}
