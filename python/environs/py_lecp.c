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
#include "../xml/py_xml.h"

#include "py_lecp.h"
#include "py_server.h"

#include "../protocols/py_authn_request.h"
#include "../protocols/py_authn_response.h"

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
  PyObject   *lecp_obj;
  LassoLecp  *lecp;
  const char *attr;

  if (CheckArgs(args, "OS:lecp_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:lecp_get_attr", &lecp_obj, &attr))
      return NULL;
  }
  else return NULL;

  lecp = LassoLecp_get(lecp_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sssssss]", "assertionConsumerServiceURL", "msg_body", "msg_url",
			 "request", "request_type", "response", "response_type");
  if (!strcmp(attr, "assertionConsumerServiceURL"))
    return (charPtrConst_wrap(lecp->assertionConsumerServiceURL));
  if (!strcmp(attr, "msg_body"))
    return (charPtrConst_wrap(LASSO_PROFILE(lecp)->msg_body));
  if (!strcmp(attr, "msg_url"))
    return (charPtrConst_wrap(LASSO_PROFILE(lecp)->msg_url));
  if (!strcmp(attr, "request"))
    return (LassoNode_wrap(LASSO_PROFILE(lecp)->request));
  if (!strcmp(attr, "request_type"))
    return (int_wrap(LASSO_PROFILE(lecp)->request_type));
  if (!strcmp(attr, "response"))
    return (LassoNode_wrap(LASSO_PROFILE(lecp)->response));
  if (!strcmp(attr, "response_type"))
    return (int_wrap(LASSO_PROFILE(lecp)->response_type));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lecp_new(PyObject *self, PyObject *args) {
  LassoLecp *lecp;
  PyObject  *server_obj;

  if (CheckArgs(args, "o:lecp_new")) {
    if(!PyArg_ParseTuple(args, (char *) "|O:lecp_new", &server_obj))
      return NULL;
  }
  else return NULL;

  lecp = lasso_lecp_new(LassoServer_get(server_obj));

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

  codeError = lasso_lecp_build_authn_request_envelope_msg(LassoLecp_get(lecp_obj));

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

  codeError = lasso_lecp_build_authn_response_envelope_msg(LassoLecp_get(lecp_obj));

  return(int_wrap(codeError));
}

PyObject *lecp_build_authn_request_msg(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gint      codeError = 0;

  if (CheckArgs(args, "O:lecp_build_authn_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:lecp_build_authn_request_msg",
			 &lecp_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_lecp_build_authn_request_msg(LassoLecp_get(lecp_obj));

  return(int_wrap(codeError));
}

PyObject *lecp_build_authn_response_msg(PyObject *self, PyObject *args){
  PyObject *lecp_obj;
  gint      codeError = 0;

  if (CheckArgs(args, "O:lecp_build_authn_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:lecp_build_authn_response_msg",
			 &lecp_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_lecp_build_authn_response_msg(LassoLecp_get(lecp_obj));

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

PyObject *lecp_init_authn_request(PyObject *self, PyObject *args) {
  PyObject *lecp_obj;
  gchar *remote_providerID;
  gint ret;
  
  if (CheckArgs(args, "OS:lecp_init_authn_request")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lecp_init_authn_request",
			 &lecp_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;
  
  ret = lasso_lecp_init_authn_request(LassoLecp_get(lecp_obj),
				       remote_providerID);
  
  return (int_wrap(ret));
}

PyObject *lecp_init_from_authn_request_msg(PyObject *self, PyObject *args) {
  PyObject *lecp_obj;
  gchar            *authn_request_msg;
  lassoHttpMethod   authn_request_method;
  gint ret;

  if (CheckArgs(args, "OSI:lecp_init_from_authn_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:lecp_init_from_authn_request_msg",
			 &lecp_obj, &authn_request_msg, &authn_request_method))
      return NULL;
  }
  else return NULL;

  ret = lasso_lecp_init_from_authn_request_msg(LassoLecp_get(lecp_obj),
						authn_request_msg,
						authn_request_method);

  return (int_wrap(ret));
}

PyObject *lecp_process_authn_request_envelope_msg(PyObject *self, PyObject *args) {
  PyObject *lecp_obj;
  gchar *remote_providerID;
  gint ret;
  
  if (CheckArgs(args, "OS:lecp_process_authn_request_envelope_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lecp_process_authn_request_envelope_msg",
			 &lecp_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;
  
  ret = lasso_lecp_process_authn_request_envelope_msg(LassoLecp_get(lecp_obj),
						      remote_providerID);
  
  return (int_wrap(ret));
}

PyObject *lecp_process_authn_response_envelope_msg(PyObject *self, PyObject *args) {
  PyObject *lecp_obj;
  gchar *remote_providerID;
  gint ret;
  
  if (CheckArgs(args, "OS:lecp_process_authn_response_envelope_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lecp_process_authn_response_envelope_msg",
			 &lecp_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;
  
  ret = lasso_lecp_process_authn_response_envelope_msg(LassoLecp_get(lecp_obj),
						       remote_providerID);
  
  return (int_wrap(ret));
}
