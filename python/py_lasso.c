/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include "lassomod.h"

#include "py_lasso.h"

PyObject *init(PyObject *self, PyObject *args) {
  return (wrap_int(lasso_init()));
}

PyObject *shutdown(PyObject *self, PyObject *args) {
  return (wrap_int(lasso_shutdown()));
}

PyObject *check_version_exact(PyObject *self, PyObject *args) {
  return (wrap_int(lasso_check_version_exact()));
}

PyObject *check_version(PyObject *self, PyObject *args) {
  return (wrap_int(lasso_check_version()));
}

PyObject *check_version_ext(PyObject *self, PyObject *args) {
  int major;
  int minor;
  int subminor;
  lassoCheckVersionMode mode;
  
  if (CheckArgs(args, "IIII:check_version_ext")) {
    if(!PyArg_ParseTuple(args, (char *) "iiii:check_version_ext",
			 &major, &minor, &subminor, &mode))
      return NULL;
  }
  else return NULL;

  return (wrap_int(lasso_check_version_ext(major, minor, subminor, mode)));
}
