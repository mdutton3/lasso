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

#ifndef __PYLASSO_PY_LIB_LOGOUT_REQUEST_H__
#define __PYLASSO_PY_LIB_LOGOUT_REQUEST_H__

#include <lasso/xml/lib_logout_request.h>

typedef struct {
  PyObject_HEAD
  LassoLibLogoutRequest *obj;
} LassoLibLogoutRequest_object;

#define LassoLibLogoutRequest_get(v) (((v) == Py_None) ? NULL : (((LassoLibLogoutRequest_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *LassoLibLogoutRequest_wrap(LassoLibLogoutRequest *request);

PyObject *lib_logout_request_new(PyObject *self, PyObject *args);
PyObject *lib_logout_request_set_consent(PyObject *self, PyObject *args);
PyObject *lib_logout_request_set_nameIdentifier(PyObject *self, PyObject *args);
PyObject *lib_logout_request_set_providerID(PyObject *self, PyObject *args);
PyObject *lib_logout_request_set_relayState(PyObject *self, PyObject *args);
PyObject *lib_logout_request_set_sessionIndex(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_LIB_LOGOUT_REQUEST_H__ */
