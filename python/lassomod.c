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
#include "xml/py_lib_authn_request.h"
#include "xml/py_lib_federation_termination_notification.h"
#include "xml/py_lib_logout_request.h"
#include "xml/py_lib_logout_response.h"
#include "xml/py_lib_name_identifier_mapping_request.h"
#include "xml/py_lib_register_name_identifier_request.h"
#include "xml/py_saml_assertion.h"
#include "xml/py_saml_authentication_statement.h"
#include "xml/py_saml_name_identifier.h"

#include "protocols/py_authn_request.h"
#include "protocols/py_authn_response.h"
#include "protocols/py_federation_termination_notification.h"
#include "protocols/py_logout_request.h"
#include "protocols/py_logout_response.h"
#include "protocols/py_name_identifier_mapping_request.h"
#include "protocols/py_name_identifier_mapping_response.h"
#include "protocols/py_register_name_identifier_request.h"
#include "protocols/py_register_name_identifier_response.h"

#include "protocols/elements/py_assertion.h"
#include "protocols/elements/py_authentication_statement.h"

static PyMethodDef lasso_methods[] = {
  /* py_lasso.h */
  {"init",                init,                METH_VARARGS},
  {"shutdown",            shutdown2,           METH_VARARGS},
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
  {"node_soap_envelop",     node_soap_envelop,     METH_VARARGS},
  {"node_verify_signature", node_verify_signature, METH_VARARGS},

  /* py_lib_authn_request.h */
  {"lib_authn_request_new",                 lib_authn_request_new,                 METH_VARARGS},
  {"lib_authn_request_set_forceAuthn",      lib_authn_request_set_forceAuthn,      METH_VARARGS},
  {"lib_authn_request_set_isPassive",       lib_authn_request_set_isPassive,       METH_VARARGS},
  {"lib_authn_request_set_nameIDPolicy",    lib_authn_request_set_nameIDPolicy,    METH_VARARGS},
  {"lib_authn_request_set_protocolProfile", lib_authn_request_set_protocolProfile, METH_VARARGS},
  {"lib_authn_request_set_relayState",      lib_authn_request_set_relayState,      METH_VARARGS},

  /* py_lib_federation_termination_notification.h */
  {"lib_federation_termination_notification_new",         lib_federation_termination_notification_new,         METH_VARARGS},
  {"lib_federation_termination_notification_set_consent", lib_federation_termination_notification_set_consent, METH_VARARGS},

  /* py_lib_logout_request.h */
  {"lib_logout_request_new",                lib_logout_request_new,                METH_VARARGS},
  {"lib_logout_request_set_consent",        lib_logout_request_set_consent,        METH_VARARGS},
  {"lib_logout_request_set_nameIdentifier", lib_logout_request_set_nameIdentifier, METH_VARARGS},
  {"lib_logout_request_set_providerID",     lib_logout_request_set_providerID,     METH_VARARGS},
  {"lib_logout_request_set_relayState",     lib_logout_request_set_relayState,     METH_VARARGS},
  {"lib_logout_request_set_sessionIndex",   lib_logout_request_set_sessionIndex,   METH_VARARGS},

  {"lib_logout_response_new",               lib_logout_response_new,               METH_VARARGS},

  /* py_lib_name_identifier_mapping_request.h */
  {"lib_name_identifier_mapping_request_new",         lib_name_identifier_mapping_request_new,         METH_VARARGS},
  {"lib_name_identifier_mapping_request_set_consent", lib_name_identifier_mapping_request_set_consent, METH_VARARGS},

  /* py_lib_register_name_identifier_request.h */
  {"lib_register_name_identifier_request_new",            lib_register_name_identifier_request_new,            METH_VARARGS},
  {"lib_register_name_identifier_request_set_relayState", lib_register_name_identifier_request_set_relayState, METH_VARARGS},

  /* py_saml_assertion.h */
  {"saml_assertion_new",                         saml_assertion_new,                         METH_VARARGS},
  {"saml_assertion_add_authenticationStatement", saml_assertion_add_authenticationStatement, METH_VARARGS},

  /* py_saml_authentication_statement.h */
  {"saml_authentication_statement_new", saml_authentication_statement_new, METH_VARARGS},

  /* py_saml_name_identifier.h */
  {"saml_name_identifier_new",               saml_name_identifier_new,               METH_VARARGS},
  {"saml_name_identifier_set_format",        saml_name_identifier_set_format,        METH_VARARGS},
  {"saml_name_identifier_set_nameQualifier", saml_name_identifier_set_nameQualifier, METH_VARARGS},

  /* protocols */
  /* py_authn_request.h */
  {"authn_request_new",                     authn_request_new,                     METH_VARARGS},
  {"authn_request_set_requestAuthnContext", authn_request_set_requestAuthnContext, METH_VARARGS},
  {"authn_request_set_scoping",             authn_request_set_scoping,             METH_VARARGS},
  {"authn_request_get_protocolProfile", authn_request_get_protocolProfile, METH_VARARGS},

  /* py_authn_response.h */
  {"authn_response_getattr",                       authn_response_getattr,                       METH_VARARGS},
  {"authn_response_new",                           authn_response_new,                           METH_VARARGS},
  {"authn_response_add_assertion",                 authn_response_add_assertion,                 METH_VARARGS},
  {"authn_response_must_authenticate",             authn_response_must_authenticate,             METH_VARARGS},
  {"authn_response_process_authentication_result", authn_response_process_authentication_result, METH_VARARGS},
  {"authn_response_verify_signature",              authn_response_verify_signature,              METH_VARARGS},

  /* py_federation_termination_notification.h */
  {"federation_termination_notification_new", federation_termination_notification_new, METH_VARARGS},

  /* py_logout_request.h */
  {"logout_request_new",                logout_request_new,                METH_VARARGS},
  {"logout_request_new_from_soap",      logout_request_new_from_soap,      METH_VARARGS},
  {"logout_request_new_from_query",     logout_request_new_from_query,     METH_VARARGS},

  /* py_logout_response.h */
  {"logout_response_new_from_request_soap",  logout_response_new_from_request_soap,  METH_VARARGS},
  {"logout_response_new_from_soap",          logout_response_new_from_soap,          METH_VARARGS},
  {"logout_response_new_from_dump",          logout_response_new_from_dump,          METH_VARARGS},
  {"logout_response_new_from_request_query", logout_response_new_from_request_query, METH_VARARGS},
  {"logout_response_new_from_query",         logout_response_new_from_query,         METH_VARARGS},

  /* py_name_identifier_mapping_request.h */
  {"name_identifier_mapping_request_new", name_identifier_mapping_request_new, METH_VARARGS},

  /* py_name_identifier_mapping_response.h */
  {"name_identifier_mapping_response_new", name_identifier_mapping_response_new, METH_VARARGS},

  /* py_register_name_identifier_request.h */
  {"register_name_identifier_request_new", register_name_identifier_request_new, METH_VARARGS},
  {"register_name_identifier_request_change_attribute_names_identifiers",
       register_name_identifier_request_change_attribute_names_identifiers, METH_VARARGS},

  /* py_register_name_identifier_response.h */
  {"register_name_identifier_response_new", register_name_identifier_response_new, METH_VARARGS},

  /* py_request.h */
/*   {"request_create", request_create, METH_VARARGS}, */
/*   {"request_getattr", request_getattr, METH_VARARGS}, */

  /* py_response.h */
/*   {"response_create", response_create, METH_VARARGS}, */
/*   {"response_getattr", response_getattr, METH_VARARGS}, */
/*   {"response_init", response_init, METH_VARARGS}, */
/*   {"response_add_assertion", response_add_assertion, METH_VARARGS}, */

  /* protocols/elements */
  /* assertion.h */
  {"assertion_new", assertion_new, METH_VARARGS},

  /* authentication_statement.h */
  {"authentication_statement_new", authentication_statement_new, METH_VARARGS},

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
