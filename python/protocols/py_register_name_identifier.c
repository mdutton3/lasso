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

#include "../lassomod.h"

#include "../xml/py_xml.h"
#include "py_register_name_identifier.h"

/******************************************************************************/
/* lassoRegisterNameIdentifierRequest                                         */
/******************************************************************************/

PyObject *lassoRegisterNameIdentifierRequest_wrap(lassoRegisterNameIdentifierRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "lassoRegisterNameIdentifierRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *register_name_identifier_request_getattr(PyObject *self, PyObject *args) {
  PyObject *request_obj;
  lassoRegisterNameIdentifierRequest *request;
  const char *attr;

  if (CheckArgs(args, "OS:register_name_identifier_request_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:register_name_identifier_request_get_attr", &request_obj, &attr))
      return NULL;
  }
  else return NULL;

  request = lassoRegisterNameIdentifierRequest_get(request_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(request->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *register_name_identifier_request_create(PyObject *self, PyObject *args) {
  const xmlChar *providerID;

  const xmlChar *idpNameIdentifier;
  const xmlChar *idpNameQualifier;
  const xmlChar *idpFormat;

  const xmlChar *spNameIdentifier;
  const xmlChar *spNameQualifier;
  const xmlChar *spFormat;

  const xmlChar *oldNameIdentifier;
  const xmlChar *oldNameQualifier;
  const xmlChar *oldFormat;

  const xmlChar *relayState;
  
  lassoRegisterNameIdentifierRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "sssssssssss:register_name_identifier_request_create",
		       &providerID,
		       &idpNameIdentifier, &idpNameQualifier, &idpFormat,
		       &spNameIdentifier, &spNameQualifier, &spFormat,
		       &oldNameIdentifier, &oldNameQualifier, &oldFormat,
		       &relayState))
    return NULL;

  request = lasso_register_name_identifier_request_create(providerID,
							  idpNameIdentifier,
							  idpNameQualifier,
							  idpFormat,
							  spNameIdentifier,
							  spNameQualifier,
							  spFormat,
							  oldNameIdentifier,
							  oldNameQualifier,
							  oldFormat,
							  relayState);

  return (lassoRegisterNameIdentifierRequest_wrap(request));
}
