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

PyObject *authn_response_new_from_export(PyObject *self, PyObject *args) {
  xmlChar   *buffer;
  gint       type;
  LassoNode *response;

  if (CheckArgs(args, "SI:authn_response_new_from_export")) {
    if(!PyArg_ParseTuple(args, (char *) "si:authn_response_new_from_export",
			 &buffer, &type))
      return NULL;
  }
  else return NULL;

  response = lasso_authn_response_new_from_export(buffer, type);

  return (LassoAuthnResponse_wrap(LASSO_AUTHN_RESPONSE(response)));
}
