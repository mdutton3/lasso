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

#include "../../lassomod.h"

#include "py_assertion.h"

PyObject *LassoAssertion_wrap(LassoAssertion *assertion) {
  PyObject *ret;

  if (assertion == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) assertion,
                                     (char *) "LassoAssertion *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *assertion_new(PyObject *self, PyObject *args) {
  const xmlChar *issuer;
  xmlChar       *requestID;
  LassoNode     *assertion;

  if (CheckArgs(args, "SS:assertion_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ss:assertion_new",
			 &issuer, &requestID))
      return NULL;
  }
  else return NULL;

  assertion = lasso_assertion_new(issuer, requestID);

  return (LassoAssertion_wrap(LASSO_ASSERTION(assertion)));
}
