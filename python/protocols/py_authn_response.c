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

#include "../xml/py_xml.h"
#include "py_authn_response.h"
#include "py_authn_request.h"

/******************************************************************************/
/* LassoAuthnResponse                                                          */
/******************************************************************************/

PyObject *LassoAuthnResponse_wrap(LassoAuthnResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "LassoAuthnResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *authn_response_new_from_dump(PyObject *self, PyObject *args) {
  xmlChar   *buffer;
  LassoNode *response;

  if (CheckArgs(args, "S:authn_response_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:authn_response_new_from_dump",
			 &buffer))
      return NULL;
  }
  else return NULL;

  response = lasso_authn_response_new_from_dump(buffer);

  return (LassoAuthnResponse_wrap(LASSO_AUTHN_RESPONSE(response)));
}

PyObject *authn_response_new_from_export(PyObject *self, PyObject *args) {
  xmlChar   *buffer;
  gint       type;
  LassoNode *response;

  if (CheckArgs(args, "Si:authn_response_new_from_export")) {
    if(!PyArg_ParseTuple(args, (char *) "si:authn_response_new_from_export",
			 &buffer, &type))
      return NULL;
  }
  else return NULL;

  response = lasso_authn_response_new_from_export(buffer, type);

  return (LassoAuthnResponse_wrap(LASSO_AUTHN_RESPONSE(response)));
}

PyObject *authn_response_new_from_request_query(PyObject *self, PyObject *args) {
  xmlChar       *query = NULL;
  const xmlChar *providerID = NULL;
  LassoNode     *response;

  if (CheckArgs(args, "ss:authn_response_new_from_request_query")) {
    if(!PyArg_ParseTuple(args, (char *) "zz:authn_response_new_from_request_query",
			 &query, &providerID))
      return NULL;
  }
  else return NULL;

  response = lasso_authn_response_new_from_request_query(query, providerID);

  return (LassoAuthnResponse_wrap(LASSO_AUTHN_RESPONSE(response)));
}

PyObject *authn_response_must_authenticate(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  gboolean is_authenticated;
  gboolean ret;

  if (CheckArgs(args, "OI:authn_response_must_authenticate")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:authn_response_must_authenticate",
			 &response_obj, &is_authenticated))
      return NULL;
  }
  else return NULL;

  ret = lasso_authn_response_must_authenticate(LassoAuthnResponse_get(response_obj),
					       is_authenticated);

  return (int_wrap(ret));
}

PyObject *authn_response_process_authentication_result(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  gboolean authentication_result;

  if (CheckArgs(args, "OI:authn_response_process_authentication_result")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:authn_response_process_authentication_result",
			 &response_obj, &authentication_result))
      return NULL;
  }
  else return NULL;

  lasso_authn_response_process_authentication_result(LassoAuthnResponse_get(response_obj),
						     authentication_result);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *authn_response_verify_signature(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  xmlChar  *public_key_file;
  xmlChar  *private_key_file;
  gboolean ret;

  if (CheckArgs(args, "OSS:authn_response_verify_signature")) {
    if(!PyArg_ParseTuple(args, (char *) "Oss:authn_response_verify_signature",
			 &response_obj, &public_key_file, &private_key_file))
      return NULL;
  }
  else return NULL;

  ret = lasso_authn_response_verify_signature(LassoAuthnResponse_get(response_obj),
					      public_key_file, private_key_file);

  return (int_wrap(ret));
}
