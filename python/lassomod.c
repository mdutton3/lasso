/* $Id$ 
 *
 * PyLasso - Python bindings for Lasso library
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

#include "lassomod.h"

#include "py_lasso.h"
#include "xml/py_xml.h"
#include "protocols/py_authn_request.h"
#include "protocols/py_logout_request.h"
#include "protocols/py_logout_response.h"
#include "protocols/py_register_name_identifier_request.h"
#include "protocols/py_register_name_identifier_response.h"
#include "protocols/py_federation_termination_notification.h"
#include "protocols/py_name_identifier_mapping_request.h"
#include "protocols/py_name_identifier_mapping_response.h"

static PyMethodDef lasso_methods[] = {
  /* py_lasso.h */
  {"init",                init,                METH_VARARGS},
  {"shutdown",            shutdown,            METH_VARARGS},
  {"check_version_exact", check_version_exact, METH_VARARGS},
  {"check_version",       check_version,       METH_VARARGS},
  {"check_version_ext",   check_version_ext,   METH_VARARGS},

  /* xml */
  /* py_xml.h */
  {"node_dump",             node_dump,             METH_VARARGS},
  {"node_get_attr_value",   node_get_attr_value,   METH_VARARGS},
  {"node_get_child",        node_get_child,        METH_VARARGS},
  {"node_unref",            node_unref,            METH_VARARGS},
  {"node_url_encode",       node_url_encode,       METH_VARARGS},
  {"node_verify_signature", node_verify_signature, METH_VARARGS},

  /* protocols */
  /* py_logout_request.h */
  {"logout_request_getattr",      logout_request_getattr,      METH_VARARGS},
  {"logout_request",              logout_request,              METH_VARARGS},

  {"logout_request_set_sessionIndex", logout_request_set_sessionIndex, METH_VARARGS},
  {"logout_request_set_relayState",   logout_request_set_relayState,   METH_VARARGS},
  {"logout_request_set_consent",      logout_request_set_consent,      METH_VARARGS},

  /* py_logout_response.h */
  {"logout_response_getattr", logout_response_getattr, METH_VARARGS},
  {"logout_response",         logout_response,         METH_VARARGS},

  /* py_register_name_identifier_request.h */
  {"register_name_identifier_request_getattr",        register_name_identifier_request_getattr,        METH_VARARGS},
  {"register_name_identifier_request",                register_name_identifier_request,                METH_VARARGS},
  {"register_name_identifier_request_change_attribute_names_identifiers",
       register_name_identifier_request_change_attribute_names_identifiers, METH_VARARGS},
  {"register_name_identifier_request_set_relayState", register_name_identifier_request_set_relayState, METH_VARARGS},

  /* py_register_name_identifier_response.h */
  {"register_name_identifier_response_getattr", register_name_identifier_response_getattr, METH_VARARGS},
  {"register_name_identifier_response",         register_name_identifier_response,         METH_VARARGS},

  /* py_authn_request.h */
  {"authn_request_new",                     authn_request_new,                     METH_VARARGS},
  {"authn_request_set_requestAuthnContext", authn_request_set_requestAuthnContext, METH_VARARGS},
  {"authn_request_set_scoping",             authn_request_set_scoping,             METH_VARARGS},

  /* py_authn_response.h */
/*   {"authn_response_getattr",       authn_response_getattr,       METH_VARARGS}, */
/*   {"authn_response_create",        authn_response_create,        METH_VARARGS}, */
/*   {"authn_response_init",          authn_response_init,          METH_VARARGS}, */
/*   {"authn_response_add_assertion", authn_response_add_assertion, METH_VARARGS}, */
/*   {"assertion_build",                       assertion_build,                       METH_VARARGS}, */
/*   {"assertion_add_authenticationStatement", assertion_add_authenticationStatement, METH_VARARGS}, */
/*   {"authentication_statement_build", authentication_statement_build, METH_VARARGS}, */

/*   {"request_create", request_create, METH_VARARGS}, */
/*   {"request_getattr", request_getattr, METH_VARARGS}, */

/*   {"response_create", response_create, METH_VARARGS}, */
/*   {"response_getattr", response_getattr, METH_VARARGS}, */
/*   {"response_init", response_init, METH_VARARGS}, */
/*   {"response_add_assertion", response_add_assertion, METH_VARARGS}, */

  /* py_federation_termination_notification.h */
  {"federation_termination_notification_getattr", federation_termination_notification_getattr, METH_VARARGS},
  {"federation_termination_notification",  federation_termination_notification,  METH_VARARGS},
  {"federation_termination_notification_set_consent",  federation_termination_notification_set_consent,  METH_VARARGS},

  /* py_name_identifier_mapping_request.h */
  {"name_identifier_mapping_request_getattr", name_identifier_mapping_request_getattr, METH_VARARGS},
  {"name_identifier_mapping_request",  name_identifier_mapping_request,  METH_VARARGS},
  {"name_identifier_mapping_request_set_consent",  name_identifier_mapping_request_set_consent,  METH_VARARGS},

  {"name_identifier_mapping_response_getattr", name_identifier_mapping_response_getattr, METH_VARARGS},
  {"name_identifier_mapping_response",  name_identifier_mapping_response,  METH_VARARGS},


  {NULL, NULL} /* End of Methods Sentinel */
};

PyObject *lasso_error;

void initlassomod(void) {
  PyObject *m, *d;
  
  m = Py_InitModule("lassomod", lasso_methods);
  d = PyModule_GetDict(m);

  lasso_error = PyErr_NewException("lassomod.error", NULL, NULL);
  PyDict_SetItemString(d, "lassomod error", lasso_error);
  Py_INCREF(lasso_error);
  PyModule_AddObject(m, "lassomod error", lasso_error);
}
