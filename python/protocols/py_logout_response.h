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

#ifndef __PYLASSO_PY_LOGOUT_RESPONSE_H__
#define __PYLASSO_PY_LOGOUT_RESPONSE_H__

#include <lasso/protocols/logout_response.h>

typedef struct {
    PyObject_HEAD
    LassoLogoutResponse *obj;
} LassoLogoutResponse_object;

#define LassoLogoutResponse_get(v) (((v) == Py_None) ? NULL : (((LassoLogoutResponse_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *LassoLogoutResponse_wrap(LassoLogoutResponse *response);

PyObject *logout_response_new_from_request_soap(PyObject *self, PyObject *args);
PyObject *logout_response_new_from_soap(PyObject *self, PyObject *args);
PyObject *logout_response_new_from_dump(PyObject *self, PyObject *args);
PyObject *logout_response_new_from_request_query(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_LOGOUT_RESPONSE_H__ */
