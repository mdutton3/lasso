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

#include "py_register_name_identifier_request.h"
#include "py_register_name_identifier_response.h"

PyObject *LassoRegisterNameIdentifierResponse_wrap(LassoRegisterNameIdentifierResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "LassoRegisterNameIdentifierResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *register_name_identifier_response_new(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *statusCodeValue;
  PyObject      *request_obj;
  LassoNode     *response;

  if (CheckArgs(args, "SSO:register_name_identifier_response_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ssO:register_name_identifier_response_new",
			 &providerID,
			 &statusCodeValue, &request_obj))
      return NULL;
  }
  else return NULL;

  response = lasso_register_name_identifier_response_new(providerID,
							 statusCodeValue,
							 LassoRegisterNameIdentifierRequest_get(request_obj));

  return (LassoRegisterNameIdentifierResponse_wrap(LASSO_REGISTER_NAME_IDENTIFIER_RESPONSE(response)));
}
