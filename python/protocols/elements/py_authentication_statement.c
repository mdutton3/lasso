/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
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

#include "../../xml/py_saml_name_identifier.h"
#include "py_authentication_statement.h"

PyObject *LassoAuthenticationStatement_wrap(LassoAuthenticationStatement *statement) {
  PyObject *ret;

  if (statement == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) statement,
                                     (char *) "LassoAuthenticationStatement *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *authentication_statement_new(PyObject *self, PyObject *args) {
  PyObject *identifier_obj, *idp_identifier_obj;
  const xmlChar *authenticationMethod;
  const xmlChar *reauthenticateOnOrAfter;
  LassoSamlNameIdentifier *identifier=NULL, *idp_identifier;
  LassoNode *statement;

  if (CheckArgs(args, "SSoO:authentication_statement_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ssOO:authentication_statement_new",
			 &authenticationMethod, &reauthenticateOnOrAfter,
			 &identifier_obj, &idp_identifier_obj))
      return NULL;
  }
  else return NULL;

  if (identifier_obj != Py_None) {
    identifier = LassoSamlNameIdentifier_get(identifier_obj);
  }
  idp_identifier = LassoSamlNameIdentifier_get(idp_identifier_obj);

  statement = lasso_authentication_statement_new(authenticationMethod,
						 reauthenticateOnOrAfter,
						 identifier,
						 idp_identifier);

  return (LassoAuthenticationStatement_wrap(LASSO_AUTHENTICATION_STATEMENT(statement)));
}
