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

#include "py_logout_response.h"
#include "py_logout_request.h"

PyObject *LassoLogoutResponse_wrap(LassoLogoutResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "LassoLogoutResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *logout_response_new(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *statusCodeValue;
  PyObject      *request_obj;

  LassoNode *response;

  if (CheckArgs(args, "SSO:logout_response_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ssO:logout_response_new",
			 &providerID,
			 &statusCodeValue, &request_obj))
      return NULL;
  }
  else return NULL;

  response = lasso_logout_response_new(providerID,
				       statusCodeValue,
				       LassoLogoutRequest_get(request_obj));

  return (LassoLogoutResponse_wrap(LASSO_LOGOUT_RESPONSE(response)));
}
