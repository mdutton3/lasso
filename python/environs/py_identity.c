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

#include "py_identity.h"
#include "../xml/py_xml.h"


PyObject *LassoIdentity_wrap(LassoIdentity *identity) {
  PyObject *ret;

  if (identity == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) identity,
                                     (char *) "LassoIdentity *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *identity_new(PyObject *self, PyObject *args) {
  return (LassoIdentity_wrap(lasso_identity_new()));
}

PyObject *identity_new_from_dump(PyObject *self, PyObject *args) {
  LassoIdentity *identity;
  gchar *dump;

  if (CheckArgs(args, "S:identity_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:identity_new_from_dump", &dump))
      return NULL;
  }
  else return NULL;

  identity = lasso_identity_new_from_dump(dump);

  return (LassoIdentity_wrap(identity));
}

PyObject *identity_dump(PyObject *self, PyObject *args) {
  PyObject  *identity_obj;
  gchar     *dump;

  if (CheckArgs(args, "O:identity_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "O:identity_dump", &identity_obj))
      return NULL;
  }
  else return NULL;

  dump = lasso_identity_dump(LassoIdentity_get(identity_obj));

  return (charPtr_wrap(dump));
}
