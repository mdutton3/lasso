/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *         Nicolas Clapies <nclapies@entrouvert.com>
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

#include "py_logout_request.h"

PyObject *LassoLogoutRequest_wrap(LassoLogoutRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoLogoutRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *logout_request_new(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *nameIdentifier;
  const xmlChar *nameQualifier;
  const xmlChar *format;

  LassoNode *request;

  if (CheckArgs(args, "SSSS:logout_request_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ssss:logout_request_new",
			 &providerID, &nameIdentifier, &nameQualifier, &format))
      return NULL;
  }
  else return NULL;

  request = lasso_logout_request_new(providerID,
				     nameIdentifier, nameQualifier, format);

  return (LassoLogoutRequest_wrap(LASSO_LOGOUT_REQUEST(request)));
}

PyObject *logout_request_new_from_soap(PyObject *self, PyObject *args) {
  const xmlChar *soap_buffer;

  LassoNode     *request;

  if (CheckArgs(args, "S:logout_request_new_from_soap")) {
    if(!PyArg_ParseTuple(args, (char *) "s:logout_request_new_from_soap",
			 &soap_buffer))
      return NULL;
  }
  else return NULL;

  request = lasso_logout_request_new_from_soap(soap_buffer);

  return (LassoLogoutRequest_wrap(LASSO_LOGOUT_REQUEST(request)));
}

PyObject *logout_request_new_from_query(PyObject *self, PyObject *args) {
  const xmlChar *query;

  LassoNode     *request;

  if (CheckArgs(args, "S:logout_request_new_from_query")) {
    if(!PyArg_ParseTuple(args, (char *) "s:logout_request_new_from_query",
			 &query))
      return NULL;
  }
  else return NULL;

  request = lasso_logout_request_new_from_query(query);

  return (LassoLogoutRequest_wrap(LASSO_LOGOUT_REQUEST(request)));
}
