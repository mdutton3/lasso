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

#include "py_samlp_response.h"

PyObject *LassoSamlpResponse_wrap(LassoSamlpResponse *node) {
  PyObject *ret;

  if (node == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) node,
                                     (char *) "LassoSamlpResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *samlp_response_new(PyObject *self, PyObject *args) {
  LassoNode *node;

  node = lasso_samlp_response_new();

  return (LassoSamlpResponse_wrap(LASSO_SAMLP_RESPONSE(node)));
}

PyObject *samlp_response_add_assertion(PyObject *self, PyObject *args) {
  PyObject *node_obj, *assertion_obj;

  if (CheckArgs(args, "OO:samlp_response_add_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:samlp_response_add_assertion",
			 &node_obj, &assertion_obj))
      return NULL;
  }
  else return NULL;

  lasso_samlp_response_add_assertion(LassoSamlpResponse_get(node_obj),
				     gpointer_get(assertion_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}
