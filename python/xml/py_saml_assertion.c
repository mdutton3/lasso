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

#include "py_saml_assertion.h"
#include "py_saml_authentication_statement.h"

PyObject *LassoSamlAssertion_wrap(LassoSamlAssertion *node) {
  PyObject *ret;

  if (node == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) node,
                                     (char *) "LassoSamlAssertion *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *saml_assertion_new(PyObject *self, PyObject *args) {
  LassoNode *node;

  node = lasso_saml_assertion_new();

  return (LassoSamlAssertion_wrap(LASSO_SAML_ASSERTION(node)));
}

PyObject *saml_assertion_add_authenticationStatement(PyObject *self, PyObject *args) {
  PyObject *node_obj, *authenticationStatement_obj;

  if (CheckArgs(args, "OO:saml_assertion_add_authenticationStatement")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:saml_assertion_add_authenticationStatement",
			 &node_obj, &authenticationStatement_obj))
      return NULL;
  }
  else return NULL;

  lasso_saml_assertion_add_authenticationStatement(LassoSamlAssertion_get(node_obj),
						   LassoSamlAuthenticationStatement_get(authenticationStatement_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}
