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

#include "py_authn_request.h"

PyObject *LassoAuthnRequest_wrap(LassoAuthnRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoAuthnRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *authn_request_new(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  LassoNode *request;
  gint sign_type, sign_method;

  if(!PyArg_ParseTuple(args, (char *) "sii:authn_request_new", &providerID,
		       &sign_type, &sign_method))
    return NULL;

  request = lasso_authn_request_new(providerID, sign_type, sign_method);

  return (LassoAuthnRequest_wrap(LASSO_AUTHN_REQUEST(request)));
}

PyObject *authn_request_set_requestAuthnContext(PyObject *self, PyObject *args) {
  PyObject *request_obj, *authnContextClassRefs_obj;
  PyObject *authnContextStatementRefs_obj;
  GPtrArray     *authnContextClassRefs = NULL;
  GPtrArray     *authnContextStatementRefs = NULL;
  const xmlChar *authnContextComparison = NULL;

  if(!PyArg_ParseTuple(args, (char *) "O|O|Oz:authn_request_set_requestAuthnContext",
		       &request_obj, &authnContextClassRefs_obj,
		       &authnContextStatementRefs_obj, &authnContextComparison))
    return NULL;

  if (authnContextClassRefs_obj != Py_None) {
    authnContextClassRefs = GPtrArray_get(authnContextClassRefs_obj);
  }
  if (authnContextStatementRefs_obj != Py_None) {
    authnContextStatementRefs = GPtrArray_get(authnContextStatementRefs_obj);
  }

  lasso_authn_request_set_requestAuthnContext(LassoAuthnRequest_get(request_obj),
					      authnContextClassRefs,
					      authnContextStatementRefs,
					      authnContextComparison);
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *authn_request_set_scoping(PyObject *self, PyObject *args) {
  PyObject *request_obj;
  gint      proxyCount;

  if(!PyArg_ParseTuple(args, (char *) "Oi:authn_request_set_scoping",
		       &request_obj, &proxyCount))
    return NULL;
  
  lasso_authn_request_set_scoping(LassoAuthnRequest_get(request_obj),
				  proxyCount);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *authn_request_get_protocolProfile(PyObject *self, PyObject *args) {
  gchar *query;
  gchar *protocolProfile;

  if(!PyArg_ParseTuple(args, (char *) "s:authn_request_get_protocolProfile",
		       &query))
    return NULL;

  protocolProfile = lasso_authn_request_get_protocolProfile(query);

  return (xmlCharPtr_wrap(protocolProfile));
}
