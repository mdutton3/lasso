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

/******************************************************************************/
/* lassoAuthnRequest                                                          */
/******************************************************************************/

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
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(lareq->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *authn_request_create(PyObject *self, PyObject *args) {
  PyObject *authnContextClassRefs_obj, *authnContextStatementRefs_obj;
  PyObject *idpList_obj;
  const xmlChar *providerID;
  const xmlChar *nameIDPolicy = NULL;
  gint           forceAuthn;
  gint           isPassive;
  const xmlChar *protocolProfile = NULL;
  const xmlChar *assertionConsumerServiceID = NULL;
  GPtrArray     *authnContextClassRefs = NULL;
  GPtrArray     *authnContextStatementRefs = NULL;
  const xmlChar *authnContextComparison = NULL;
  const xmlChar *relayState = NULL;
  gint           proxyCount;
  GPtrArray     *idpList = NULL;
  const xmlChar *consent = NULL;

  lassoAuthnRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "sziizz|O|OzziOz:authn_request_create",
		       &providerID, &nameIDPolicy, &forceAuthn, &isPassive,
		       &protocolProfile, &assertionConsumerServiceID,
		       &authnContextClassRefs_obj, &authnContextStatementRefs_obj,
		       &authnContextComparison, &relayState, &proxyCount,
		       &idpList_obj, &consent))
    return NULL;

  if (authnContextClassRefs_obj != Py_None) {
    authnContextClassRefs = PythonStringList2_get(authnContextClassRefs_obj);
  }
  if (authnContextStatementRefs_obj != Py_None) {
    authnContextStatementRefs = PythonStringList2_get(authnContextStatementRefs_obj);
  }
  if (idpList_obj != Py_None) {
    idpList = PythonStringList2_get(idpList_obj);
  }

  request = lasso_authn_request_create(providerID,
				       nameIDPolicy,
				       forceAuthn,
				       isPassive,
				       protocolProfile,
				       assertionConsumerServiceID,
				       authnContextClassRefs,
				       authnContextStatementRefs,
				       authnContextComparison,
				       relayState,
				       proxyCount,
				       NULL,
				       consent);

  return (lassoAuthnRequest_wrap(request));
}

/******************************************************************************/
/* lassoAuthnResponse                                                         */
/******************************************************************************/

PyObject *lassoAuthnResponse_wrap(lassoAuthnResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "lassoAuthnResponse *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *authn_response_getattr(PyObject *self, PyObject *args) {
  PyObject *reponse_obj;
  lassoAuthnResponse *reponse;
  const char *attr;

  if (CheckArgs(args, "OS:authn_response_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:authn_response_get_attr", &reponse_obj, &attr))
      return NULL;
  }
  else return NULL;

  reponse = lassoAuthnResponse_get(reponse_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sss]", "node", "isPassive", "mustAuthenticate");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(reponse->node));
  if (!strcmp(attr, "isPassive"))
    return (int_wrap(reponse->isPassive));
  if (!strcmp(attr, "mustAuthenticate"))
    return (int_wrap(reponse->mustAuthenticate));

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *authn_response_create(PyObject *self, PyObject *args) {
  xmlChar       *query;
  gboolean       verify_signature;
  const xmlChar *public_key_file;
  const xmlChar *private_key_file;
  const xmlChar *certificate_file;
  gboolean       is_authenticated;

  lassoAuthnResponse *response;

  if(!PyArg_ParseTuple(args, (char *) "sisssi:authn_response_create",
		       &query, &verify_signature, &public_key_file, &private_key_file,
		       &certificate_file, &is_authenticated))
    return NULL;

  response = lasso_authn_response_create(query,
					 verify_signature,
					 public_key_file,
					 private_key_file,
					 certificate_file,
					 is_authenticated);

  return (lassoAuthnResponse_wrap(response));
}

PyObject *authn_response_init(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  const xmlChar *providerID;
  gboolean       authentication_result;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "Osi:authn_response_init",
		       &response_obj, &providerID, &authentication_result))
    return NULL;

  ret = lasso_authn_response_init(lassoAuthnResponse_get(response_obj),
				  providerID, authentication_result);

  return (int_wrap(ret));
}

PyObject *authn_response_add_assertion(PyObject *self, PyObject *args) {
  PyObject *response_obj, *assertion_obj;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "OO:authn_response_add_assertion",
		       &response_obj, &assertion_obj))
    return NULL;

  ret = lasso_authn_response_add_assertion(lassoAuthnResponse_get(response_obj),
					   LassoNode_get(assertion_obj));

  return (int_wrap(ret));
}

/******************************************************************************/
/* assertion                                                                  */
/******************************************************************************/

PyObject *assertion_build(PyObject *self, PyObject *args) {
  PyObject *response_obj;
  xmlChar *issuer;
  LassoNode *assertion;

  if(!PyArg_ParseTuple(args, (char *) "Os:assertion_build",
		       &response_obj, &issuer))
    return NULL;
  
  assertion = lasso_assertion_build(lassoAuthnResponse_get(response_obj),
				    issuer);
  return (LassoNode_wrap(assertion));
}

PyObject *assertion_add_authenticationStatement(PyObject *self, PyObject *args) {
  PyObject *assertion_obj, *statement_obj;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "OO:assertion_add_authenticationStatement",
		       &assertion_obj, &statement_obj))
    return NULL;

  ret = lasso_assertion_add_authenticationStatement(LassoNode_get(assertion_obj),
						    LassoNode_get(statement_obj));

  return (int_wrap(ret));
}

/******************************************************************************/
/* authentication statement                                                   */
/******************************************************************************/

PyObject *authentication_statement_build(PyObject *self, PyObject *args) {
  xmlChar *authenticationMethod;
  xmlChar *sessionIndex;
  xmlChar *reauthenticateOnOrAfter;
  xmlChar *nameIdentifier;
  xmlChar *nameQualifier;
  xmlChar *format;
  xmlChar *idp_nameIdentifier;
  xmlChar *idp_nameQualifier;
  xmlChar *idp_format;
  xmlChar *confirmationMethod;
  LassoNode *statement;

  if(!PyArg_ParseTuple(args, (char *) "szsssssssz:authentication_statement_build",
		       &authenticationMethod, &sessionIndex, &reauthenticateOnOrAfter,
		       &nameIdentifier, &nameQualifier, &format, &idp_nameIdentifier,
		       &idp_nameQualifier, &idp_format, &confirmationMethod))
    return NULL;

  statement = lasso_authentication_statement_build(authenticationMethod, sessionIndex,
						   reauthenticateOnOrAfter,
						   nameIdentifier, nameQualifier,
						   format, idp_nameIdentifier,
						   idp_nameQualifier, idp_format,
						   confirmationMethod);

  return (LassoNode_wrap(statement));
}

/******************************************************************************/
/* lassoRequest                                                               */
/******************************************************************************/

PyObject *lassoRequest_wrap(lassoRequest *request) {
  PyObject *ret;

  if (request == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) request,
                                     (char *) "lassoRequest *", NULL);
  return (ret);
}

PyObject *request_getattr(PyObject *self, PyObject *args) {
  PyObject *lareq_obj;
  lassoRequest *lareq;
  const char *attr;

  if (CheckArgs(args, "OS:request_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:request_get_attr", &lareq_obj, &attr))
      return NULL;
  }
  else return NULL;

  lareq = lassoRequest_get(lareq_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(lareq->node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *request_create(PyObject *self, PyObject *args) {
  const xmlChar *assertionArtifact;

  lassoRequest *request;

  if(!PyArg_ParseTuple(args, (char *) "s:request_create",
		       &assertionArtifact))
    return NULL;

  request = lasso_request_create(assertionArtifact);

  return (lassoRequest_wrap(request));
}

/******************************************************************************/
/* lassoResponse                                                              */
/******************************************************************************/

PyObject *lassoResponse_wrap(lassoResponse *response) {
  PyObject *ret;

  if (response == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) response,
                                     (char *) "lassoResponse *", NULL);
  return (ret);
}

PyObject *response_getattr(PyObject *self, PyObject *args) {
  PyObject *lares_obj;
  lassoResponse *lares;
  const char *attr;

  if (CheckArgs(args, "OS:response_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:response_get_attr", &lares_obj, &attr))
      return NULL;
  }
  else return NULL;

  lares = lassoResponse_get(lares_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "node");
  if (!strcmp(attr, "node"))
    return (LassoNode_wrap(lares->node));
  if (!strcmp(attr, "request_node"))
    return (LassoNode_wrap(lares->request_node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *response_create(PyObject *self, PyObject *args) {
  const char    *serialized_request;
  int            verifySignature;
  const char    *public_key;
  const char    *private_key;
  const char    *certificate;

  lassoResponse *response;

  if(!PyArg_ParseTuple(args, (char *) "sisss:response_create",
		       &serialized_request, &verifySignature, &public_key, &private_key, &certificate))
    return NULL;

  response = lasso_response_create(serialized_request,
				   verifySignature,
				   public_key,
				   private_key,
				   certificate);

  return (lassoResponse_wrap(response));
}

PyObject *response_init(PyObject *self, PyObject *args) {
  PyObject      *response_obj;
  gboolean       authentication_result;
  int            ret;

  if(!PyArg_ParseTuple(args, (char *) "Oi:response_init",
		       &response_obj, &authentication_result))
    return NULL;

  ret = lasso_response_init(lassoResponse_get(response_obj),
			    authentication_result);

  return (int_wrap(ret));
}

PyObject *response_add_assertion(PyObject *self, PyObject *args) {
  PyObject *response_obj, *assertion_obj;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "OO:response_add_assertion",
		       &response_obj, &assertion_obj))
    return NULL;

  ret = lasso_response_add_assertion(lassoResponse_get(response_obj),
				     LassoNode_get(assertion_obj));

  return (int_wrap(ret));
}
