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

#include "py_lib_register_name_identifier_request.h"

PyObject *LassoLibRegisterNameIdentifierRequest_wrap(LassoLibRegisterNameIdentifierRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "LassoLibRegisterNameIdentifierRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *lib_register_name_identifier_request_new(PyObject *self, PyObject *args) {
  LassoNode *node;

  node = lasso_lib_register_name_identifier_request_new();

  return (LassoLibRegisterNameIdentifierRequest_wrap(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node)));
}

PyObject *lib_register_name_identifier_request_set_relayState(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *relayState;

  if (CheckArgs(args, "OS:lib_register_name_identifier_request_set_relayState")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_register_name_identifier_request_set_relayState",
			 &node_obj, &relayState))
      return NULL;
  }
  else return NULL;
     
  lasso_lib_register_name_identifier_request_set_relayState(LassoLibRegisterNameIdentifierRequest_get(node_obj),
							    relayState);
  
  Py_INCREF(Py_None);
  return (Py_None);
}
