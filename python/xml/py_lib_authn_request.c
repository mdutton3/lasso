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

#include "py_lib_authn_request.h"

PyObject *LassoLibAuthnRequest_wrap(LassoLibAuthnRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoLibAuthnRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *lib_authn_request_new(PyObject *self, PyObject *args) {
  LassoNode *request;

  request = lasso_lib_authn_request_new();

  return (LassoLibAuthnRequest_wrap(LASSO_LIB_AUTHN_REQUEST(request)));
}

PyObject *lib_authn_request_set_forceAuthn(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  gint      forceAuthn;

  if (CheckArgs(args, "OI:lib_authn_request_set_forceAuthn")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:lib_authn_request_set_forceAuthn",
			 &node_obj, &forceAuthn))
      return NULL;
  }
  else return NULL;

  lasso_lib_authn_request_set_forceAuthn(LassoLibAuthnRequest_get(node_obj),
					 forceAuthn);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_authn_request_set_isPassive(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  gint      isPassive;

  if (CheckArgs(args, "OI:lib_authn_request_set_isPassive")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:lib_authn_request_set_isPassive",
			 &node_obj, &isPassive))
      return NULL;
  }
  else return NULL;

  lasso_lib_authn_request_set_isPassive(LassoLibAuthnRequest_get(node_obj),
					isPassive);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_authn_request_set_nameIDPolicy(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *nameIDPolicy;

  if (CheckArgs(args, "OS:lib_authn_request_set_nameIDPolicy")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_authn_request_set_nameIDPolicy",
			 &node_obj, &nameIDPolicy))
      return NULL;
  }
  else return NULL;

  lasso_lib_authn_request_set_nameIDPolicy(LassoLibAuthnRequest_get(node_obj),
					   nameIDPolicy);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_authn_request_set_protocolProfile(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *protocolProfile;

  if (CheckArgs(args, "OS:lib_authn_request_set_protocolProfile")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_authn_request_set_protocolProfile",
			 &node_obj, &protocolProfile))
      return NULL;
  }
  else return NULL;

  lasso_lib_authn_request_set_protocolProfile(LassoLibAuthnRequest_get(node_obj),
					      protocolProfile);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_authn_request_set_relayState(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *relayState;

  if (CheckArgs(args, "OS:lib_authn_request_set_relayState")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_authn_request_set_relayState",
			 &node_obj, &relayState))
      return NULL;
  }
  else return NULL;

  lasso_lib_authn_request_set_relayState(LassoLibAuthnRequest_get(node_obj),
					 relayState);

  Py_INCREF(Py_None);
  return (Py_None);
}
