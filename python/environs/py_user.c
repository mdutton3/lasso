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

#include "py_user.h"

PyObject *LassoUser_wrap(LassoUser *user) {
  PyObject *ret;

  if (user == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) user,
                                     (char *) "LassoUser *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *user_new(PyObject *self, PyObject *args) {
  return (LassoUser_wrap(lasso_user_new()));
}

PyObject *user_new_from_dump(PyObject *self, PyObject *args) {
  LassoUser *user;
  gchar *dump;

  if (CheckArgs(args, "S:user_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:user_new_from_dump", &dump))
      return NULL;
  }
  else return NULL;

  user = lasso_user_new_from_dump(dump);

  return (LassoUser_wrap(user));
}
