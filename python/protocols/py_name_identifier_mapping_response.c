/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
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

#include "py_name_identifier_mapping_response.h"
#include "py_name_identifier_mapping_request.h"

PyObject *LassoNameIdentifierMappingResponse_wrap(LassoNameIdentifierMappingResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "LassoNameIdentifierMappingResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *name_identifier_mapping_response_new_from_request_soap(PyObject *self, PyObject *args) {
  const xmlChar *request_soap_dump;
  const xmlChar *providerID;
  const xmlChar *status_code_value;

  LassoNode *response = NULL;

  if (CheckArgs(args, "SSS:name_identifier_mapping_response_new_from_request_soap")) {
    if(!PyArg_ParseTuple(args, (char *) "sss:name_identifier_mapping_response_new_from_request_soap",
			 &request_soap_dump,
			 &providerID,
			 &status_code_value))
      return NULL;
  }
  else return NULL;

  response = lasso_name_identifier_mapping_response_new_from_request_soap(request_soap_dump,
									  providerID,
									  status_code_value);

  return (LassoNameIdentifierMappingResponse_wrap(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(response)));
}

PyObject *name_identifier_mapping_response_new_from_soap(PyObject *self, PyObject *args) {
  const xmlChar *response_soap_dump;

  LassoNode *response = NULL;

  if (CheckArgs(args, "S:name_identifier_mapping_response_new_from_soap")) {
    if(!PyArg_ParseTuple(args, (char *) "s:name_identifier_mapping_response_new_from_soap",
			 &response_soap_dump))
      return NULL;
  }
  else return NULL;

  response = lasso_name_identifier_mapping_response_new_from_soap(response_soap_dump);

  return (LassoNameIdentifierMappingResponse_wrap(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(response)));
}

PyObject *name_identifier_mapping_response_new_from_dump(PyObject *self, PyObject *args) {
  const xmlChar *dump;

  LassoNode *response = NULL;

  if (CheckArgs(args, "S:name_identifier_mapping_response_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:name_identifier_mapping_response_new_from_dump",
			 &dump))
      return NULL;
  }
  else return NULL;

  response = lasso_name_identifier_mapping_response_new_from_soap(dump);

  return (LassoNameIdentifierMappingResponse_wrap(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(response)));
}

PyObject *name_identifier_mapping_response_new_from_request_query(PyObject *self, PyObject *args) {
  const xmlChar *query;
  const xmlChar *providerID;
  const xmlChar *status_code_value;

  LassoNode *response = NULL;

  if (CheckArgs(args, "SSS:name_identifier_mapping_response_new_from_request_query")) {
    if(!PyArg_ParseTuple(args, (char *) "sss:name_identifier_mapping_response_new_from_request_query",
			 &query,
			 &providerID,
			 &status_code_value))
      return NULL;
  }
  else return NULL;

  response = lasso_name_identifier_mapping_response_new_from_request_query(query, providerID, status_code_value);

  return (LassoNameIdentifierMappingResponse_wrap(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(response)));
}

PyObject *name_identifier_mapping_response_new_from_query(PyObject *self, PyObject *args) {
  const xmlChar *query;

  LassoNode *response = NULL;

  if (CheckArgs(args, "S:name_identifier_mapping_response_new_from_query")) {
    if(!PyArg_ParseTuple(args, (char *) "s:name_identifier_mapping_response_new_from_query",
			 &query))
      return NULL;
  }
  else return NULL;

  response = lasso_name_identifier_mapping_response_new_from_query(query);

  return (LassoNameIdentifierMappingResponse_wrap(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(response)));
}
