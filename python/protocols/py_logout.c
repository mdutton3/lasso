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
#include "py_logout.h"

/******************************************************************************/
/* lassoLogoutRequest                                                         */
/******************************************************************************/

PyObject *lassoLogoutRequest_wrap(lassoLogoutRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "lassoLogoutRequest *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *logout_request_getattr(PyObject *self, PyObject *args) {
  PyObject *request_obj;
  lassoLogoutRequest *request;
  const char *attr;

  if (CheckArgs(args, "OS:logout_request_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:logout_request_get_attr", &request_obj, &attr))
      return NULL;
  }
  else return NULL;

  request = lassoLogoutRequest_get(request_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(request->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *logout_request_create(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *nameIdentifier;
  const xmlChar *nameQualifier;
  const xmlChar *format;
  const xmlChar *sessionIndex;
  const xmlChar *relayState;
  const xmlChar *consent;

  lassoLogoutRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "sssssss:logout_request_create",
		       &providerID,
		       &nameIdentifier, &nameQualifier, &format,
		       &sessionIndex,
		       &relayState,
		       &consent))
    return NULL;

  request = lasso_logout_request_create(providerID,
					nameIdentifier,
					nameQualifier,
					format,
					sessionIndex,
					relayState,
					consent);

  return (lassoLogoutRequest_wrap(request));
}
