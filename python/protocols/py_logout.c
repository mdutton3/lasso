/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
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

#include "../lassomod.h"

#include "../xml/py_xml.h"
#include "py_logout.h"

/******************************************************************************/
/* lassoLogoutRequest                                                         */
/******************************************************************************/

PyObject *lassoLogoutRequest_wrap(lassoLogoutRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "lassoLogoutRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *logout_request_getattr(PyObject *self, PyObject *args) {
  PyObject *request_obj;
  lassoLogoutRequest *request;
  const char *attr;

  if (CheckArgs(args, "OS:logout_request_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:logout_request_get_attr", &request_obj, &attr))
      return NULL;
  }
  else return NULL;

  request = lassoLogoutRequest_get(request_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(request->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *logout_request_create(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *nameIdentifier;
  const xmlChar *nameQualifier;
  const xmlChar *format;
  const xmlChar *sessionIndex;
  const xmlChar *relayState;
  const xmlChar *consent;

  lassoLogoutRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "sssssss:logout_request_create",
		       &providerID,
		       &nameIdentifier, &nameQualifier, &format,
		       &sessionIndex,
		       &relayState,
		       &consent))
    return NULL;

  request = lasso_logout_request_create(providerID,
					nameIdentifier,
					nameQualifier,
					format,
					sessionIndex,
					relayState,
					consent);

  return (lassoLogoutRequest_wrap(request));
}

/******************************************************************************/
/* lassoLogoutResponse                                                        */
/******************************************************************************/

PyObject *lassoLogoutResponse_wrap(lassoLogoutResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "lassoLogoutResponse *", NULL);
  return (ret);
}

PyObject *logout_response_getattr(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  lassoLogoutResponse *response;
  const char *attr;

  if (CheckArgs(args, "OS:logout_response_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:logout_response_get_attr", &response_obj, &attr))
      return NULL;
  }
  else return NULL;

  response = lassoLogoutResponse_get(response_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(response->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *logout_response_create(PyObject *self, PyObject *args) {
  char *query;
  int   verifySignature;
  char *public_key;
  char *private_key;
  char *certificate;

  lassoLogoutResponse *response;

  if(!PyArg_ParseTuple(args, (char *) "sisss:logout_response_create",
		       &query,
		       &verifySignature,
		       &public_key,
		       &private_key,
		       &certificate))
    return NULL;

  response = lasso_logout_response_create(query,
					  verifySignature,
					  public_key,
					  private_key,
					  certificate);

  return (lassoLogoutResponse_wrap(response));
}

PyObject *logout_response_init(PyObject *self, PyObject *args) {
  PyObject      *response_obj;
  char          *providerID;
  char          *statusCodeValue;
  char          *relayState;
  int            ret;

  if(!PyArg_ParseTuple(args, (char *) "Osss:response_init",
		       &response_obj,
		       &providerID,
		       &statusCodeValue,
		       &relayState))
    return NULL;

  ret = lasso_logout_response_init(lassoLogoutResponse_get(response_obj),
				   providerID,
				   statusCodeValue,
				   relayState);

  return (int_wrap(ret));
}
