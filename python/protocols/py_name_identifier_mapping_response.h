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

#ifndef __PYLASSO_PY_NAME_IDENTIFIER_MAPPING_RESPONSE_H__
#define __PYLASSO_PY_NAME_IDENTIFIER_MAPPING_RESPONSE_H__

#include <lasso/protocols/name_identifier_mapping_response.h>

typedef struct {
    PyObject_HEAD
    LassoNameIdentifierMappingResponse *obj;
} LassoNameIdentifierMappingResponse_object;

#define lassoNameIdentifierMappingResponse_get(v) (((v) == Py_None) ? NULL : (((LassoNameIdentifierMappingResponse_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
PyObject *lassoNameIdentifierMappingResponse_wrap(LassoNameIdentifierMappingResponse *response);

PyObject *name_identifier_mapping_response_getattr(PyObject *self, PyObject *args);
PyObject *name_identifier_mapping_response(PyObject *self, PyObject *args);

#endif /* __PYLASSO_PY_NAME_IDENTIFIER_MAPPING_RESPONSE_H__ */
