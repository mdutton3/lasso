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

#ifndef __PYLASSO_PY_USER_H__
#define __PYLASSO_PY_USER_H__

#include <lasso/environs/user.h>

typedef struct {
    PyObject_HEAD
    LassoUser *obj;
} LassoUser_object;

#define LassoUser_get(v) (((v) == Py_None) ? NULL : (((LassoUser_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *LassoUser_wrap(LassoUser *user);

PyObject *user_new(PyObject *self, PyObject *args);
PyObject *user_new_from_dump(PyObject *self, PyObject *args);

PyObject *user_add_assertion(PyObject *self, PyObject *args);
PyObject *user_destroy(PyObject *self, PyObject *args);
PyObject *user_dump(PyObject *self, PyObject *args);
PyObject *user_get_assertion(PyObject *self, PyObject *args);
PyObject *user_get_authentication_method(PyObject *self, PyObject *args);
PyObject *user_get_next_assertion_remote_providerID(PyObject *self, PyObject *args);
PyObject *user_remove_assertion(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_USER_H__ */
