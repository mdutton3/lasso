/* $Id$ 
 *
 * PyLasso - Python bindings for Lasso library
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

#include "lassomod.h"

#include "py_lasso.h"

#include "xml/py_xml.h"
#include "xml/py_lib_authentication_statement.h"
#include "xml/py_lib_authn_request.h"
#include "xml/py_lib_authn_response.h"
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

#include "environs/py_federation_termination.h"
#include "environs/py_identity.h"
#include "environs/py_lecp.h"
#include "environs/py_login.h"
#include "environs/py_logout.h"
#include "environs/py_profile.h"
#include "environs/py_register_name_identifier.h"
#include "environs/py_server.h"
#include "environs/py_session.h"

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
  {"lib_authn_request_set_consent",         lib_authn_request_set_consent,         METH_VARARGS},
  {"lib_authn_request_set_forceAuthn",      lib_authn_request_set_forceAuthn,      METH_VARARGS},
  {"lib_authn_request_set_isPassive",       lib_authn_request_set_isPassive,       METH_VARARGS},
  {"lib_authn_request_set_nameIDPolicy",    lib_authn_request_set_nameIDPolicy,    METH_VARARGS},
  {"lib_authn_request_set_protocolProfile", lib_authn_request_set_protocolProfile, METH_VARARGS},
  {"lib_authn_request_set_relayState",      lib_authn_request_set_relayState,      METH_VARARGS},

  /* py_lib_authn_response.h */
/*   {"lib_authn_response_new",                 lib_authn_response_new,                 METH_VARARGS}, */
/*   {"lib_authn_response_add_assertion",       lib_authn_response_add_assertion,       METH_VARARGS}, */

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
  {"federation_termination_notification_new",             federation_termination_notification_new,             METH_VARARGS},
  {"federation_termination_notification_new_from_export", federation_termination_notification_new_from_export, METH_VARARGS},

  /* py_logout_request.h */
  {"logout_request_new",                logout_request_new,                METH_VARARGS},
  {"logout_request_new_from_export",    logout_request_new_from_export,    METH_VARARGS},

  /* py_logout_response.h */
  {"logout_response_new_from_request_export",  logout_response_new_from_request_export,  METH_VARARGS},
  {"logout_response_new_from_export",          logout_response_new_from_export,          METH_VARARGS},

  /* py_name_identifier_mapping_request.h */
  {"name_identifier_mapping_request_new",             name_identifier_mapping_request_new,             METH_VARARGS},
/*   {"name_identifier_mapping_request_new_from_export", name_identifier_mapping_request_new_from_export, METH_VARARGS}, */

  /* py_name_identifier_mapping_response.h */
/*   {"name_identifier_mapping_response_new_from_request_export", name_identifier_mapping_response_new_from_request_export, METH_VARARGS}, */
/*   {"name_identifier_mapping_response_new_from_export",         name_identifier_mapping_response_new_from_export,         METH_VARARGS}, */

  /* py_register_name_identifier_request.h */
  {"register_name_identifier_request_new", register_name_identifier_request_new, METH_VARARGS},
  {"register_name_identifier_request_rename_attributes_for_query", register_name_identifier_request_rename_attributes_for_query, METH_VARARGS},

  /* py_register_name_identifier_response.h */
  {"register_name_identifier_response_new_from_request_export", register_name_identifier_response_new_from_request_export, METH_VARARGS},
  {"register_name_identifier_response_new_from_export",         register_name_identifier_response_new_from_export,         METH_VARARGS},

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
  {"profile_get_request_type_from_soap_msg", profile_get_request_type_from_soap_msg, METH_VARARGS},
  {"profile_new",                            profile_new,                            METH_VARARGS},
  {"profile_get_identity",                   profile_get_identity,                   METH_VARARGS},
  {"profile_get_session",                    profile_get_session,                    METH_VARARGS},
  {"profile_is_identity_dirty",              profile_is_identity_dirty,              METH_VARARGS},
  {"profile_is_session_dirty",               profile_is_session_dirty,               METH_VARARGS},
  {"profile_set_identity",                   profile_set_identity,                   METH_VARARGS},
  {"profile_set_identity_from_dump",         profile_set_identity_from_dump,         METH_VARARGS},
  {"profile_set_session",                    profile_set_session,                    METH_VARARGS},
  {"profile_set_session_from_dump",          profile_set_session_from_dump,          METH_VARARGS},

  /* py_identity.h */
  {"identity_new",           identity_new,           METH_VARARGS},
  {"identity_new_from_dump", identity_new_from_dump, METH_VARARGS},
  {"identity_dump",          identity_dump,          METH_VARARGS},

  /* py_federation_termination.h */
  {"federation_termination_getattr", federation_termination_getattr, METH_VARARGS},
  {"federation_termination_new",                      federation_termination_new,                      METH_VARARGS},
  {"federation_termination_build_notification_msg",   federation_termination_build_notification_msg,   METH_VARARGS},
  {"federation_termination_destroy",                  federation_termination_destroy,                  METH_VARARGS},
  {"federation_termination_init_notification",        federation_termination_init_notification,        METH_VARARGS},
  {"federation_termination_process_notification_msg", federation_termination_process_notification_msg, METH_VARARGS},
  {"federation_termination_validate_notification",    federation_termination_validate_notification,    METH_VARARGS},

  /* py_lecp.h */
  {"lecp_new",                                 lecp_new,                                 METH_VARARGS},
  {"lecp_getattr",                             lecp_getattr,                             METH_VARARGS},
  {"lecp_build_authn_request_envelope_msg",    lecp_build_authn_request_envelope_msg,    METH_VARARGS},
  {"lecp_build_authn_request_msg",             lecp_build_authn_request_msg,             METH_VARARGS},
  {"lecp_build_authn_response_msg",            lecp_build_authn_response_msg,            METH_VARARGS},
  {"lecp_build_authn_response_envelope_msg",   lecp_build_authn_response_envelope_msg,   METH_VARARGS},
  {"lecp_destroy",                             lecp_destroy,                             METH_VARARGS},
  {"lecp_init_authn_request",                  lecp_init_authn_request,                  METH_VARARGS},
  {"lecp_init_from_authn_request_msg",         lecp_init_from_authn_request_msg,         METH_VARARGS},
  {"lecp_process_authn_request_envelope_msg",  lecp_process_authn_request_envelope_msg,  METH_VARARGS},
  {"lecp_process_authn_response_envelope_msg", lecp_process_authn_response_envelope_msg, METH_VARARGS},

  /* py_login.h */
  {"login_getattr", login_getattr, METH_VARARGS},
  {"login_new",                         login_new,                         METH_VARARGS},
  {"login_new_from_dump",               login_new_from_dump,               METH_VARARGS},
  {"login_accept_sso",                  login_accept_sso,                  METH_VARARGS},
  {"login_build_artifact_msg",          login_build_artifact_msg,          METH_VARARGS},
  {"login_build_authn_request_msg",     login_build_authn_request_msg,     METH_VARARGS},
  {"login_build_authn_response_msg",    login_build_authn_response_msg,    METH_VARARGS},
  {"login_build_request_msg",           login_build_request_msg,           METH_VARARGS},
  {"login_dump",                        login_dump,                        METH_VARARGS},
  {"login_init_authn_request",          login_init_authn_request,          METH_VARARGS},
  {"login_init_from_authn_request_msg", login_init_from_authn_request_msg, METH_VARARGS},
  {"login_init_request",                login_init_request,                METH_VARARGS},
  {"login_must_authenticate",           login_must_authenticate,           METH_VARARGS},
  {"login_process_authn_response_msg",  login_process_authn_response_msg,  METH_VARARGS},
  {"login_process_request_msg",         login_process_request_msg,         METH_VARARGS},
  {"login_process_response_msg",        login_process_response_msg,        METH_VARARGS},

  /* py_logout.h */
  {"logout_getattr",              logout_getattr,              METH_VARARGS},
  {"logout_new",                  logout_new,                  METH_VARARGS},
  {"logout_build_request_msg",    logout_build_request_msg,    METH_VARARGS},
  {"logout_build_response_msg",   logout_build_response_msg,   METH_VARARGS},
  {"logout_destroy",              logout_destroy,              METH_VARARGS},
  {"logout_get_next_providerID",  logout_get_next_providerID,  METH_VARARGS},
  {"logout_init_request",         logout_init_request,         METH_VARARGS},
  {"logout_process_request_msg",  logout_process_request_msg,  METH_VARARGS},
  {"logout_process_response_msg", logout_process_response_msg, METH_VARARGS},
  {"logout_validate_request",     logout_validate_request,     METH_VARARGS},

  /* py_register_name_identifier.h */
  {"register_name_identifier_getattr",              register_name_identifier_getattr,              METH_VARARGS},
  {"register_name_identifier_new",                  register_name_identifier_new,                  METH_VARARGS},
  {"register_name_identifier_build_request_msg",    register_name_identifier_build_request_msg,    METH_VARARGS},
  {"register_name_identifier_build_response_msg",   register_name_identifier_build_response_msg,   METH_VARARGS},
  {"register_name_identifier_destroy",              register_name_identifier_destroy,              METH_VARARGS},
  {"register_name_identifier_init_request",         register_name_identifier_init_request,         METH_VARARGS},
  {"register_name_identifier_process_request_msg",  register_name_identifier_process_request_msg,  METH_VARARGS},
  {"register_name_identifier_process_response_msg", register_name_identifier_process_response_msg, METH_VARARGS},

  /* py_server.h */
  {"server_new",           server_new,           METH_VARARGS},
  {"server_new_from_dump", server_new_from_dump, METH_VARARGS},
  {"server_add_provider",  server_add_provider,  METH_VARARGS},
  {"server_destroy",       server_destroy,       METH_VARARGS},
  {"server_dump",          server_dump,          METH_VARARGS},
  
  /* py_session.h */
  {"session_getattr", session_getattr, METH_VARARGS},
  {"session_new",                                  session_new,                                  METH_VARARGS},
  {"session_new_from_dump",                        session_new_from_dump,                        METH_VARARGS},
  {"session_add_assertion",                        session_add_assertion,                        METH_VARARGS},
  {"session_destroy",                              session_destroy,                              METH_VARARGS},
  {"session_dump",                                 session_dump,                                 METH_VARARGS},
  {"session_get_assertion",                        session_get_assertion,                        METH_VARARGS},
  {"session_get_authentication_method",            session_get_authentication_method,            METH_VARARGS},
  {"session_get_next_assertion_remote_providerID", session_get_next_assertion_remote_providerID, METH_VARARGS},
  {"session_remove_assertion",                     session_remove_assertion,                     METH_VARARGS},

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
