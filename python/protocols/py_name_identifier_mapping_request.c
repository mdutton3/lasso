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

PyObject *lassoNameIdentifierMappingRequest_wrap(LassoNameIdentifierMappingRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoNameIdentifierMappingRequest *", NULL);
  return (ret);
}

PyObject *name_identifier_mapping_request_getattr(PyObject *self, PyObject *args) {
  PyObject *request_obj;
  LassoNameIdentifierMappingRequest *request;
  const char *attr;

  if (CheckArgs(args, "OS:name_identifier_mapping_request_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:name_identifier_mapping_request_get_attr", &request_obj, &attr))
      return NULL;
  }
  else return NULL;

  request = lassoNameIdentifierMappingRequest_get(request_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *name_identifier_mapping_request(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *nameIdentifier;
  const xmlChar *nameQualifier;
  const xmlChar *format;

  LassoNameIdentifierMappingRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "ssss:name_identifier_mapping_request",
		       &providerID,
		       &nameIdentifier, &nameQualifier, &format))
    return NULL;

  request = (LassoNameIdentifierMappingRequest *)lasso_name_identifier_mapping_request_new(providerID,
							   nameIdentifier,
							   nameQualifier,
							   format);

  return (lassoNameIdentifierMappingRequest_wrap(request));
}

PyObject *name_identifier_mapping_request_set_consent(PyObject *self, PyObject *args){
     PyObject      *request_obj;
     const xmlChar *consent;
     
     if(!PyArg_ParseTuple(args, (char *) "Os:name_identifier_mapping_request_set_consent",
			  &request_obj, &consent))
	  return NULL;

     lasso_lib_name_identifier_mapping_request_set_consent(lassoNameIdentifierMappingRequest_get(request_obj),
					  consent);
     
     return (int_wrap(1));
}
