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

PyObject *logout_response_new_from_request_export(PyObject *self, PyObject *args) {
  gchar *request_export;
  gchar *providerID;
  gchar *status_code_value;
  gint   export_type;

  LassoNode *response = NULL;

  if (CheckArgs(args, "SSSS:logout_response_new_from_request_export")) {
    if(!PyArg_ParseTuple(args, (char *) "ssss:logout_response_new_from_request_export",
			 &request_export,
			 &export_type,
			 &providerID,
			 &status_code_value))
      return NULL;
  }
  else return NULL;

  response = lasso_logout_response_new_from_request_export(request_export,
							   export_type,
							   providerID,
							   status_code_value);

  return (LassoLogoutResponse_wrap(LASSO_LOGOUT_RESPONSE(response)));
}

PyObject *logout_response_new_from_export(PyObject *self, PyObject *args) {
  gchar *request_export;
  gint   export_type;

  LassoNode *response = NULL;

  if (CheckArgs(args, "SS:logout_response_new_from_export")) {
    if(!PyArg_ParseTuple(args, (char *) "ss:logout_response_new_from_export",
			 &request_export, &export_type))
      return NULL;
  }
  else return NULL;

  response = lasso_logout_response_new_from_export(request_export, export_type);

  return (LassoLogoutResponse_wrap(LASSO_LOGOUT_RESPONSE(response)));
}
