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

#include "py_lib_authn_response.h"

PyObject *LassoLibAuthnResponse_wrap(LassoLibAuthnResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "LassoLibAuthnResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *lib_authn_response_new(PyObject *self, PyObject *args) {
  LassoNode *response;

  response = lasso_lib_authn_response_new();

  return (LassoLibAuthnResponse_wrap(LASSO_LIB_AUTHN_RESPONSE(response)));
}

PyObject *lib_authn_response_set_relayState(PyObject *self, PyObject *args) {
  PyObject      *node_obj;
  const xmlChar *relayState;

  if (CheckArgs(args, "OS:lib_authn_response_set_relayState")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_authn_response_set_relayState",
			 &node_obj, &relayState))
      return NULL;
  }
  else return NULL;

  lasso_lib_authn_response_set_relayState(LassoLibAuthnResponse_get(node_obj),
					 relayState);

  Py_INCREF(Py_None);
  return (Py_None);
}
