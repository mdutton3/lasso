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
#include "xml/py_lib_authentication_statement.h"
#include "xml/py_lib_authn_request.h"
#include "xml/py_lib_federation_termination_notification.h"
#include "xml/py_lib_logout_request.h"
#include "xml/py_lib_logout_response.h"
#include "xml/py_lib_name_identifier_mapping_request.h"
#include "xml/py_lib_name_identifier_mapping_response.h"
#include "xml/py_lib_register_name_identifier_request.h"
#include "xml/py_saml_assertion.h"
#include "xml/py_saml_authentication_statement.h"
#include "xml/py_saml_name_identifier.h"
#include "xml/py_samlp_response.h"

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

#include "environs/py_login.h"
#include "environs/py_logout.h"
#include "environs/py_server.h"
#include "environs/py_user.h"

static PyMethodDef lasso_methods[] = {
  /* py_lasso.h */
  {"init",                init,                METH_VARARGS},
  {"shutdown",            shutdown2,           METH_VARARGS},
  {"check_version_exact", check_version_exact, METH_VARARGS},
  {"check_version",       check_version,       METH_VARARGS},
  {"check_version_ext",   check_version_ext,   METH_VARARGS},

  /* xml */
  /* py_xml.h */
  {"node_destroy",          node_destroy,          METH_VARARGS},
  {"node_dump",             node_dump,             METH_VARARGS},
  {"node_export",           node_export,           METH_VARARGS},
  {"node_export_to_base64", node_export_to_base64, METH_VARARGS},
  {"node_export_to_query",  node_export_to_query,  METH_VARARGS},
  {"node_export_to_soap",   node_export_to_soap,   METH_VARARGS},
  {"node_get_attr_value",   node_get_attr_value,   METH_VARARGS},
  {"node_get_child",        node_get_child,        METH_VARARGS},
  {"node_get_content",      node_get_content,      METH_VARARGS},
  {"node_verify_signature", node_verify_signature, METH_VARARGS},

  /* py_lib_authentication_statement.h */
  {"lib_authentication_statement_new",              lib_authentication_statement_new,              METH_VARARGS},
  {"lib_authentication_statement_set_sessionIndex", lib_authentication_statement_set_sessionIndex, METH_VARARGS},

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

  /* py_lib_name_identifier_mapping_response.h */
  {"lib_name_identifier_mapping_response_new",         lib_name_identifier_mapping_response_new,         METH_VARARGS},

  /* py_lib_register_name_identifier_request.h */
  {"lib_register_name_identifier_request_new",            lib_register_name_identifier_request_new,            METH_VARARGS},
  {"lib_register_name_identifier_request_set_relayState", lib_register_name_identifier_request_set_relayState, METH_VARARGS},

  /* py_saml_assertion.h */
  {"saml_assertion_new",                         saml_assertion_new,                         METH_VARARGS},
  {"saml_assertion_add_authenticationStatement", saml_assertion_add_authenticationStatement, METH_VARARGS},
  {"saml_assertion_set_signature",               saml_assertion_set_signature,               METH_VARARGS},

  /* py_saml_authentication_statement.h */
  {"saml_authentication_statement_new", saml_authentication_statement_new, METH_VARARGS},

  /* py_saml_name_identifier.h */
  {"saml_name_identifier_new",               saml_name_identifier_new,               METH_VARARGS},
  {"saml_name_identifier_set_format",        saml_name_identifier_set_format,        METH_VARARGS},
  {"saml_name_identifier_set_nameQualifier", saml_name_identifier_set_nameQualifier, METH_VARARGS},

  /* py_samlp_response.h */
  {"samlp_response_new",           samlp_response_new,           METH_VARARGS},
  {"samlp_response_add_assertion", samlp_response_add_assertion, METH_VARARGS},

  /* protocols */
  /* py_authn_request.h */
  {"authn_request_new",                     authn_request_new,                     METH_VARARGS},
  {"authn_request_set_requestAuthnContext", authn_request_set_requestAuthnContext, METH_VARARGS},
  {"authn_request_set_scoping",             authn_request_set_scoping,             METH_VARARGS},
  {"authn_request_get_protocolProfile", authn_request_get_protocolProfile, METH_VARARGS},

  /* py_authn_response.h */
  {"authn_response_new_from_export",               authn_response_new_from_export,               METH_VARARGS},

  /* py_federation_termination_notification.h */
  {"federation_termination_notification_new", federation_termination_notification_new, METH_VARARGS},
  {"federation_termination_notification_new_from_soap", federation_termination_notification_new_from_soap, METH_VARARGS},
  {"federation_termination_notification_new_from_query", federation_termination_notification_new_from_query, METH_VARARGS},

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
  {"name_identifier_mapping_request_new",            name_identifier_mapping_request_new,            METH_VARARGS},
  {"name_identifier_mapping_request_new_from_soap",  name_identifier_mapping_request_new_from_soap,  METH_VARARGS},
  {"name_identifier_mapping_request_new_from_query", name_identifier_mapping_request_new_from_query, METH_VARARGS},

  /* py_name_identifier_mapping_response.h */
  {"name_identifier_mapping_response_new_from_request_soap",  name_identifier_mapping_response_new_from_request_soap,  METH_VARARGS},
  {"name_identifier_mapping_response_new_from_soap",          name_identifier_mapping_response_new_from_soap,          METH_VARARGS},
  {"name_identifier_mapping_response_new_from_dump",          name_identifier_mapping_response_new_from_dump,          METH_VARARGS},
  {"name_identifier_mapping_response_new_from_request_query", name_identifier_mapping_response_new_from_request_query, METH_VARARGS},
  {"name_identifier_mapping_response_new_from_query",         name_identifier_mapping_response_new_from_query,         METH_VARARGS},

  /* py_register_name_identifier_request.h */
  {"register_name_identifier_request_new", register_name_identifier_request_new, METH_VARARGS},
  {"register_name_identifier_request_rename_attributes_for_query", register_name_identifier_request_rename_attributes_for_query, METH_VARARGS},

  /* py_register_name_identifier_response.h */
  {"register_name_identifier_response_new_from_request_soap",  register_name_identifier_response_new_from_request_soap,  METH_VARARGS},
  {"register_name_identifier_response_new_from_soap",          register_name_identifier_response_new_from_soap,          METH_VARARGS},
  {"register_name_identifier_response_new_from_dump",          register_name_identifier_response_new_from_dump,          METH_VARARGS},
  {"register_name_identifier_response_new_from_request_query", register_name_identifier_response_new_from_request_query, METH_VARARGS},
  {"register_name_identifier_response_new_from_query",         register_name_identifier_response_new_from_query,         METH_VARARGS},

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

  /* environs */
  /* py_login.h */
  {"login_getattr",                     login_getattr,                     METH_VARARGS},
  {"login_new",                         login_new,                         METH_VARARGS},
  {"login_new_from_dump",               login_new_from_dump,               METH_VARARGS},
  {"login_build_artifact_msg",          login_build_artifact_msg,          METH_VARARGS},
  {"login_build_authn_request_msg",     login_build_authn_request_msg,     METH_VARARGS},
  {"login_build_request_msg",           login_build_request_msg,           METH_VARARGS},
  {"login_init_authn_request",          login_init_authn_request,          METH_VARARGS},
  {"login_init_from_authn_request_msg", login_init_from_authn_request_msg, METH_VARARGS},
  {"login_init_request",                login_init_request,                METH_VARARGS},
  {"login_must_authenticate",           login_must_authenticate,           METH_VARARGS},

  /* py_logout.h */
  {"logout_new",                logout_new,                METH_VARARGS},
  {"logout_build_request_msg",  logout_build_request_msg,  METH_VARARGS},
  {"logout_build_response_msg", logout_build_response_msg, METH_VARARGS},
  {"logout_init_request",       logout_init_request,       METH_VARARGS},
  {"logout_handle_request_msg",     logout_handle_request_msg,     METH_VARARGS},
  {"logout_handle_response_msg",    logout_handle_response_msg,    METH_VARARGS},

  /* py_server.h */
  {"server_new",          server_new,          METH_VARARGS},
  {"server_add_provider", server_add_provider, METH_VARARGS},
  
  /* py_user.h */
  {"user_new",           user_new,           METH_VARARGS},
  {"user_new_from_dump", user_new_from_dump, METH_VARARGS},


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
