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
#include "py_single_sign_on_and_federation.h"

PyObject *lassoAuthnRequest_wrap(lassoAuthnRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "lassoAuthnRequest *", NULL);
  return (ret);
}

/******************************************************************************/
/* lassoAuthnRequest                                                          */
/******************************************************************************/

PyObject *authn_request_getattr(PyObject *self, PyObject *args) {
  PyObject *lareq_obj;
  lassoAuthnRequest *lareq;
  const char *attr;

  if (CheckArgs(args, "OS:authn_request_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:authn_request_get_attr", &lareq_obj, &attr))
      return NULL;
  }
  else return NULL;

  lareq = lassoAuthnRequest_get(lareq_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "request"))
    return (LassoNode_wrap(lareq->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *authn_request_create(PyObject *self, PyObject *args) {
  PyObject *authnContextClassRefs_obj, *authnContextStatementRefs_obj;
  PyObject *idpList_obj;
  const xmlChar *providerID;
  const xmlChar *nameIDPolicy;
  const xmlChar *forceAuthn;
  const xmlChar *isPassive;
  const xmlChar *protocolProfile;
  const xmlChar *assertionConsumerServiceID;
  GPtrArray     *authnContextClassRefs = NULL;
  GPtrArray     *authnContextStatementRefs = NULL;
  const xmlChar *authnContextComparison;
  const xmlChar *relayState;
  gint           proxyCount;
  GPtrArray     *idpList = NULL;
  const xmlChar *consent;

  lassoAuthnRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "ssssssOOssiOs:build_authn_request",
		       &providerID, &nameIDPolicy, &forceAuthn, &isPassive,
		       &protocolProfile, &assertionConsumerServiceID,
		       &authnContextClassRefs, &authnContextStatementRefs,
		       &authnContextComparison, &relayState, &proxyCount,
		       &idpList, &consent))
    return NULL;

  request = lasso_authn_request_create(providerID,
				       nameIDPolicy,
				       forceAuthn,
				       isPassive,
				       protocolProfile,
				       assertionConsumerServiceID,
				       NULL,
				       NULL,
				       authnContextComparison,
				       relayState,
				       proxyCount,
				       NULL,
				       consent);

  return (lassoAuthnRequest_wrap(request));
}
