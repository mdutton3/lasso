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

#ifndef __PYLASSO_PY_LOGIN_H__
#define __PYLASSO_PY_LOGIN_H__

#include <lasso/environs/login.h>

#include "py_server.h"
#include "py_identity.h"

typedef struct {
    PyObject_HEAD
    LassoLogin *obj;
} LassoLogin_object;

#define LassoLogin_get(v) (((v) == Py_None) ? NULL : (((LassoLogin_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *LassoLogin_wrap(LassoLogin *login);

PyObject *login_getattr(PyObject *self, PyObject *args);
PyObject *login_new(PyObject *self, PyObject *args);
PyObject *login_new_from_dump(PyObject *self, PyObject *args);
PyObject *login_accept_sso(PyObject *self, PyObject *args);
PyObject *login_build_artifact_msg(PyObject *self, PyObject *args);
PyObject *login_build_authn_request_msg(PyObject *self, PyObject *args);
PyObject *login_build_authn_response_msg(PyObject *self, PyObject *args);
PyObject *login_build_request_msg(PyObject *self, PyObject *args);
PyObject *login_dump(PyObject *self, PyObject *args);
PyObject *login_init_authn_request(PyObject *self, PyObject *args);
PyObject *login_init_from_authn_request_msg(PyObject *self, PyObject *args);
PyObject *login_init_request(PyObject *self, PyObject *args);
PyObject *login_must_authenticate(PyObject *self, PyObject *args);
PyObject *login_process_authn_response_msg(PyObject *self, PyObject *args);
PyObject *login_process_request_msg(PyObject *self, PyObject *args);
PyObject *login_process_response_msg(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_LOGIN_H__ */
