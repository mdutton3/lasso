/* $Id$ 
 *
 * PyLasso - Python bindings for Lasso library
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

static PyMethodDef lasso_methods[] = {
  /* py_lasso.h */
  {"init",                init,                METH_VARARGS},
  {"shutdown",            shutdown,            METH_VARARGS},
  {"check_version_exact", check_version_exact, METH_VARARGS},
  {"check_version",       check_version,       METH_VARARGS},
  {"check_version_ext",   check_version_ext,   METH_VARARGS},

  {NULL, NULL} /* End of Methods Sentinel */
};

PyObject *lasso_error;

void initlassomod(void) {
  PyObject *m, *d;
  
  m = Py_InitModule("lassomod", lasso_methods);
  d = PyModule_GetDict(m);

  lasso_error = PyErr_NewException("lassomod.error", NULL, NULL);
  PyDict_SetItemString(d, "lassomod error", lasso_error);
  Py_INCREF(lasso_error);
  PyModule_AddObject(m, "lassomod error", lasso_error);
}
