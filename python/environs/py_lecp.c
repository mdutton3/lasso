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

#include "py_lecp.h"

PyObject *LassoLecp_wrap(LassoLecp *lecp) {
  PyObject *ret;

  if (lecp == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) lecp,
                                     (char *) "LassoLecp *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *lecp_getattr(PyObject *self, PyObject *args) {
  PyObject *lecp_obj;
  LassoLecp *lecp;
  const char *attr;

  if (CheckArgs(args, "OS:lecp_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:lecp_get_attr", &lecp_obj, &attr))
      return NULL;
  }
  else return NULL;

  lecp = LassoLecp_get(lecp_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssss]", "user", "msg_url", "msg_body",
			 "msg_relayState");
  if (!strcmp(attr, "msg_url"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(lecp)->msg_url));
  if (!strcmp(attr, "msg_body"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(lecp)->msg_body));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lecp_new(PyObject *self, PyObject *args) {
  LassoLecp *lecp;

  if (CheckArgs(args, ":lecp_new")) {
    if(!PyArg_ParseTuple(args, (char *) ":lecp_new"))
      return NULL;
  }
  else return NULL;

  lecp = lasso_lecp_new();

  return (LassoLecp_wrap(lecp));
}

PyObject *lecp_build_authn_request_envelope_msg(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gint      codeError = 0;

  if (CheckArgs(args, "O:lecp_build_authn_request_envelope_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:lecp_build_authn_request_envelope_msg",
			 &lecp_obj))
      return NULL;
  }
  else return NULL;

/*   codeError = lasso_lecp_build_authn_request_envelope_msg(LassoLecp_get(lecp_obj)); */

  return(int_wrap(codeError));
}

PyObject *lecp_build_authn_response_envelope_msg(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gint      codeError = 0;

  if (CheckArgs(args, "O:lecp_build_authn_response_envelope_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:lecp_build_authn_response_envelope_msg",
			 &lecp_obj))
      return NULL;
  }
  else return NULL;

/*   codeError = lecp_build_authn_response_envelope_msg(LassoLecp_get(lecp_obj)); */

  return(int_wrap(codeError));
}

PyObject *lecp_destroy(PyObject *self, PyObject *args){
  PyObject *lecp_obj;

  if (CheckArgs(args, "O:lecp_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:lecp_destroy",
			 &lecp_obj))
      return NULL;
  }
  else return NULL;

  lasso_lecp_destroy(LassoLecp_get(lecp_obj));

  Py_INCREF(Py_None);
  return(Py_None);
}

PyObject *lecp_init_authn_request_envelope(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gchar    *remote_providerID;
  gint      codeError = 0;

  if (CheckArgs(args, "Os:lecp_init_authn_request_envelope")) {
    if(!PyArg_ParseTuple(args, (char *) "Oz:lecp_init_authn_request_envelope",
			 &lecp_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

/*   codeError = lecp_init_authn_request_envelope(LassoLecp_get(lecp_obj), remote_providerID); */

  return(int_wrap(codeError));
}

PyObject *lecp_init_authn_response_envelope(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gchar    *remote_providerID;
  gint      codeError = 0;

  if (CheckArgs(args, "Os:lecp_init_authn_response_envelope")) {
    if(!PyArg_ParseTuple(args, (char *) "Oz:lecp_init_authn_response_envelope",
			 &lecp_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

/*   codeError = lecp_init_authn_request_envelope(LassoLecp_get(lecp_obj), remote_providerID); */

  return(int_wrap(codeError));
}

PyObject *lecp_process_authn_request_envelope_msg(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gchar    *request_msg;
  gint      request_method;
  gint      codeError = 0;

  if (CheckArgs(args, "OSI:lecp_process_authn_request_envelope_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:lecp_process_authn_request_envelope_msg",
			 &lecp_obj, &request_msg, &request_method))
      return NULL;
  }
  else return NULL;

/*   codeError = lasso_lecp_process_authn_request_envelope_msg(LassoLecp_get(lecp_obj), request_msg, request_method); */

  return(int_wrap(codeError));
}

PyObject *lecp_process_authn_response_envelope_msg(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gchar    *response_msg;
  gint      response_method;
  gint      codeError = 0;

  if (CheckArgs(args, "OSI:lecp_process_authn_response_envelope_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:lecp_process_authn_response_envelope_msg",
			 &lecp_obj, &response_msg, &response_method))
      return NULL;
  }
  else return NULL;

/*   codeError = lasso_lecp_process_authn_response_envelope_msg(LassoLecp_get(lecp_obj), response_msg, response_method); */

  return(int_wrap(codeError));
}
