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


#ifndef __PYLASSO_PY_REGISTER_NAME_IDENTIFIER_H__
#define __PYLASSO_PY_REGISTER_NAME_IDENTIFIER_H__

#include <lasso/environs/register_name_identifier.h>

#include "py_server.h"
#include "py_identity.h"

typedef struct {
    PyObject_HEAD
    LassoRegisterNameIdentifier *obj;
} LassoRegisterNameIdentifier_object;

#define LassoRegisterNameIdentifier_get(v) (((v) == Py_None) ? NULL : (((LassoRegisterNameIdentifier_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *LassoRegisterNameIdentifier_wrap(LassoRegisterNameIdentifier *register_name_identifier);

PyObject *register_name_identifier_getattr(PyObject *self, PyObject *args);

PyObject *register_name_identifier_build_request_msg(PyObject *self, PyObject *args);
PyObject *register_name_identifier_build_response_msg(PyObject *self, PyObject *args);
PyObject *register_name_identifier_destroy(PyObject *self, PyObject *args);
PyObject *register_name_identifier_init_request(PyObject *self, PyObject *args);
PyObject *register_name_identifier_new(PyObject *self, PyObject *args);
PyObject *register_name_identifier_process_request_msg(PyObject *self, PyObject *args);
PyObject *register_name_identifier_process_response_msg(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_REGISTER_NAME_IDENTIFIER_H__ */
