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

#include "../xml/py_xml.h"
#include "py_name_identifier_mapping_request.h"
#include "py_name_identifier_mapping_response.h"

PyObject *lassoNameIdentifierMappingResponse_wrap(LassoNameIdentifierMappingResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "LassoNameIdentifierMappingResponse *", NULL);
  return (ret);
}

PyObject *name_identifier_mapping_response_getattr(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  LassoNameIdentifierMappingResponse *response;
  const char *attr;

  if (CheckArgs(args, "OS:name_identifier_mapping_response_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:name_identifier_mapping_response_get_attr", &response_obj, &attr))
      return NULL;
  }
  else return NULL;

  response = lassoNameIdentifierMappingResponse_get(response_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *name_identifier_mapping_response(PyObject *self, PyObject *args) {
  const xmlChar      *providerID;
  const xmlChar      *statusCodeValue;
  PyObject           *request_obj;

  LassoNameIdentifierMappingResponse *response;

  if(!PyArg_ParseTuple(args, (char *) "ssO:name_identifier_mapping_response",
		       &providerID,
		       &statusCodeValue, &request_obj))
    return NULL;

  response = (LassoNameIdentifierMappingResponse *)lasso_name_identifier_mapping_response_new(providerID,
							      statusCodeValue,
							      lassoNameIdentifierMappingRequest_get(request_obj));

  return (lassoNameIdentifierMappingResponse_wrap(response));
}
