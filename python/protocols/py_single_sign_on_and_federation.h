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

#ifndef __PYLASSO_PY_SINGLE_SIGN_ON_AND_FEDERATION_H__
#define __PYLASSO_PY_SINGLE_SIGN_ON_AND_FEDERATION_H__

#include <lasso/protocols/single_sign_on_and_federation.h>

typedef struct {
    PyObject_HEAD
    lassoAuthnRequest *obj;
} lassoAuthnRequest_object;

#define lassoAuthnRequest_get(v) (((v) == Py_None) ? NULL : (((lassoAuthnRequest_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *lassoAuthnRequest_wrap(lassoAuthnRequest *request);

PyObject *authn_request_getattr(PyObject *self, PyObject *args);
PyObject *authn_request_build(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_SINGLE_SIGN_ON_AND_FEDERATION_H__ */
