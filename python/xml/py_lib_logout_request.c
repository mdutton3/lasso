/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
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

#include "../lassomod.h"

#include "py_lib_logout_request.h"
#include "py_saml_name_identifier.h"

PyObject *LassoLibLogoutRequest_wrap(LassoLibLogoutRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoLibLogoutRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *lib_logout_request_new(PyObject *self, PyObject *args) {
  LassoNode *request;

  request = lasso_lib_logout_request_new();

  return (LassoLibLogoutRequest_wrap(LASSO_LIB_LOGOUT_REQUEST(request)));
}

PyObject *lib_logout_request_set_consent(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *consent;

  if (CheckArgs(args, "OS:lib_logout_request_set_consent")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_logout_request_set_consent",
			 &node_obj, &consent))
      return NULL;
  }
  else return NULL;

  lasso_lib_logout_request_set_consent(LassoLibLogoutRequest_get(node_obj),
				       consent);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_logout_request_set_nameIdentifier(PyObject *self, PyObject *args) {
  PyObject *node_obj, *nameIdentifier_obj;

  if (CheckArgs(args, "OO:lib_logout_request_set_nameIdentifier")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:lib_logout_request_set_nameIdentifier",
			 &node_obj, &nameIdentifier_obj))
      return NULL;
  }
  else return NULL;

  lasso_lib_logout_request_set_nameIdentifier(LassoLibLogoutRequest_get(node_obj),
					      LassoSamlNameIdentifier_get(nameIdentifier_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_logout_request_set_providerID(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *providerID;

  if (CheckArgs(args, "OS:lib_logout_request_set_providerID")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_logout_request_set_providerID",
			 &node_obj, &providerID))
      return NULL;
  }
  else return NULL;

  lasso_lib_logout_request_set_providerID(LassoLibLogoutRequest_get(node_obj),
					  providerID);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_logout_request_set_relayState(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *relayState;

  if (CheckArgs(args, "OS:lib_logout_request_set_relayState")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_logout_request_set_relayState",
			 &node_obj, &relayState))
      return NULL;
  }
  else return NULL;

  lasso_lib_logout_request_set_relayState(LassoLibLogoutRequest_get(node_obj),
					  relayState);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *lib_logout_request_set_sessionIndex(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *sessionIndex;

  if (CheckArgs(args, "OS:lib_logout_request_set_sessionIndex")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_logout_request_set_sessionIndex",
			 &node_obj, &sessionIndex))
      return NULL;
  }
  else return NULL;

  lasso_lib_logout_request_set_sessionIndex(LassoLibLogoutRequest_get(node_obj),
					    sessionIndex);

  Py_INCREF(Py_None);
  return (Py_None);
}
