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

PyObject *authn_response_getattr(PyObject *self, PyObject *args) {
  PyObject *reponse_obj;
  LassoAuthnResponse *reponse;
  const char *attr;

  if (CheckArgs(args, "OS:authn_response_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:authn_response_get_attr", &reponse_obj, &attr))
      return NULL;
  }
  else return NULL;

  reponse = LassoAuthnResponse_get(reponse_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ss]", "requestID", "query");
  if (!strcmp(attr, "requestID"))
    return (xmlCharPtr_wrap(reponse->requestID));
  if (!strcmp(attr, "query"))
    return (xmlCharPtr_wrap(reponse->query));

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *authn_response_new(PyObject *self, PyObject *args) {
  xmlChar       *query;
  const xmlChar *providerID;
  LassoNode     *response;

  if (CheckArgs(args, "SS:authn_response_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ss:authn_response_new", &query,
			 &providerID))
      return NULL;
  }
  else return NULL;

  response = lasso_authn_response_new(query, providerID);

  return (LassoAuthnResponse_wrap(LASSO_AUTHN_RESPONSE(response)));
}

PyObject *authn_response_add_assertion(PyObject *self, PyObject *args) {
  PyObject *response_obj, *assertion_obj;
  const xmlChar *private_key_file;
  const xmlChar *certificate_file;

  if (CheckArgs(args, "OOSS:authn_response_add_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "OOss:authn_response_add_assertion",
			 &response_obj, &assertion_obj,
			 &private_key_file, &certificate_file))
      return NULL;
  }
  else return NULL;

  lasso_authn_response_add_assertion(LassoAuthnResponse_get(response_obj),
				     LassoAssertion_get(assertion_obj),
				     private_key_file,
				     certificate_file);

  Py_INCREF(Py_None);
  return (Py_None);
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
