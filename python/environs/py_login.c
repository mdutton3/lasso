/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include "py_login.h"

PyObject *LassoLogin_wrap(LassoLogin *login) {
  PyObject *ret;

  if (login == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) login,
                                     (char *) "LassoLogin *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *login_getattr(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  LassoLogin *login;
  const char *attr;

  if (CheckArgs(args, "OS:login_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:login_get_attr", &login_obj, &attr))
      return NULL;
  }
  else return NULL;

  login = LassoLogin_get(login_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssssssss]", "request", "response", "request_type", "response_dump",
			 "msg_url", "msg_body", "protocolProfile", "assertionArtifact");
  if (!strcmp(attr, "request"))
    return (LassoNode_wrap(LASSO_PROFILE_CONTEXT(login)->request));
  if (!strcmp(attr, "response"))
    return (LassoNode_wrap(LASSO_PROFILE_CONTEXT(login)->response));
  if (!strcmp(attr, "request_type"))
    return (int_wrap(LASSO_PROFILE_CONTEXT(login)->request_type));
  if (!strcmp(attr, "response_dump"))
    return (charPtrConst_wrap(login->response_dump));
  if (!strcmp(attr, "msg_url"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(login)->msg_url));
  if (!strcmp(attr, "msg_body"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(login)->msg_body));
  if (!strcmp(attr, "protocolProfile"))
    return (int_wrap(login->protocolProfile));
  if (!strcmp(attr, "assertionArtifact"))
    return (charPtrConst_wrap(login->assertionArtifact));

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *login_new(PyObject *self, PyObject *args) {
  PyObject *server_obj, *user_obj;
  LassoLogin *login;
  LassoServer *server;
  LassoUser   *user = NULL;

  if (CheckArgs(args, "Oo:login_new")) {
    if(!PyArg_ParseTuple(args, (char *) "O|O:login_new", &server_obj, &user_obj))
      return NULL;
  }
  else return NULL;

  server = LassoServer_get(server_obj);
  if (user_obj != Py_None) {
    user = LassoUser_get(user_obj);
  }
  login = LASSO_LOGIN(lasso_login_new(server, user));

  return (LassoLogin_wrap(login));
}

PyObject *login_new_from_dump(PyObject *self, PyObject *args) {
  PyObject *server_obj, *user_obj;
  LassoLogin *login;
  LassoServer *server;
  LassoUser   *user = NULL;
  gchar       *dump;

  if (CheckArgs(args, "OoS:login_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "OOs:login_new_from_dump", &server_obj,
			 &user_obj, &dump))
      return NULL;
  }
  else return NULL;

  server = LassoServer_get(server_obj);
  if (user_obj != Py_None) {
    user = LassoUser_get(user_obj);
  }
  login = LASSO_LOGIN(lasso_login_new_from_dump(server, user, dump));

  return (LassoLogin_wrap(login));
}

PyObject *login_build_artifact_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gint              authentication_result;
  const gchar      *authenticationMethod;
  const gchar      *reauthenticateOnOrAfter;
  lassoHttpMethods  method;
  gint ret;

  if (CheckArgs(args, "OISSI:login_build_artifact_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Oissi:login_build_artifact_msg",
			 &login_obj, &authentication_result,
			 &authenticationMethod, &reauthenticateOnOrAfter,
			 &method))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_build_artifact_msg(LassoLogin_get(login_obj),
				       authentication_result,
				       authenticationMethod,
				       reauthenticateOnOrAfter,
				       method);

  return (int_wrap(ret));
}

PyObject *login_build_authn_request_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gint ret;

  if (CheckArgs(args, "O:login_build_authn_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:login_build_authn_request_msg",
			 &login_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_build_authn_request_msg(LassoLogin_get(login_obj));

  return (int_wrap(ret));
}

PyObject *login_build_authn_response_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gint         authentication_result;
  const gchar *authenticationMethod;
  const gchar *reauthenticateOnOrAfter;
  gint ret;

  if (CheckArgs(args, "OISS:login_build_artifact_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Oiss:login_build_artifact_msg",
			 &login_obj, &authentication_result,
			 &authenticationMethod, &reauthenticateOnOrAfter))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_build_authn_response_msg(LassoLogin_get(login_obj),
					     authentication_result,
					     authenticationMethod,
					     reauthenticateOnOrAfter);

  return (int_wrap(ret));
}

PyObject *login_build_request_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gint ret;

  if (CheckArgs(args, "O:login_build_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:login_build_request_msg",
			 &login_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_build_request_msg(LassoLogin_get(login_obj));

  return (int_wrap(ret));
}

PyObject *login_dump(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar *ret;

  if (CheckArgs(args, "O:login_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "O:login_dump",
			 &login_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_dump(LassoLogin_get(login_obj));

  return (charPtrConst_wrap(ret));
}

PyObject *login_init_authn_request(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar *remote_providerID;
  gint ret;
  
  if (CheckArgs(args, "OS:login_init_authn_request")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:login_init_authn_request",
			 &login_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;
  
  ret = lasso_login_init_authn_request(LassoLogin_get(login_obj),
				       remote_providerID);
  
  return (int_wrap(ret));
}

PyObject *login_init_from_authn_request_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar            *authn_request_msg;
  lassoHttpMethods  authn_request_method;
  gint ret;

  if (CheckArgs(args, "OSI:login_init_from_authn_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:login_init_from_authn_request_msg",
			 &login_obj, &authn_request_msg, &authn_request_method))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_init_from_authn_request_msg(LassoLogin_get(login_obj),
						authn_request_msg,
						authn_request_method);

  return (int_wrap(ret));
}

PyObject *login_init_request(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar            *response_msg;
  lassoHttpMethods  response_method;
  const gchar      *remote_providerID;
  gint ret;

  if (CheckArgs(args, "OSIS:login_init_request")) {
    if(!PyArg_ParseTuple(args, (char *) "Osis:login_init_request",
			 &login_obj, &response_msg,
			 &response_method, &remote_providerID))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_init_request(LassoLogin_get(login_obj),
				 response_msg,
				 response_method,
				 remote_providerID);

  return (int_wrap(ret));
}

PyObject *login_must_authenticate(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gboolean ret;

  if (CheckArgs(args, "O:login_must_authenticate")) {
    if(!PyArg_ParseTuple(args, (char *) "O:login_must_authenticate",
			 &login_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_must_authenticate(LassoLogin_get(login_obj));

  return (int_wrap(ret));
}

PyObject *login_process_authn_response_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar    *authn_response_msg;
  gboolean ret;

  if (CheckArgs(args, "OS:login_process_authn_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:login_process_authn_response_msg",
			 &login_obj, &authn_response_msg))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_process_authn_response_msg(LassoLogin_get(login_obj),
					      authn_response_msg);

  return (int_wrap(ret));
}

PyObject *login_process_request_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar    *request_msg;
  gboolean ret;

  if (CheckArgs(args, "OS:login_process_request_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:login_process_request_msg",
			 &login_obj, &request_msg))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_process_request_msg(LassoLogin_get(login_obj),
				       request_msg);

  return (int_wrap(ret));
}

PyObject *login_process_response_msg(PyObject *self, PyObject *args) {
  PyObject *login_obj;
  gchar    *response_msg;
  gchar    *remote_providerID;
  gboolean ret;

  if (CheckArgs(args, "OSS:login_process_response_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Oss:login_process_response_msg",
			 &login_obj, &response_msg, &remote_providerID))
      return NULL;
  }
  else return NULL;

  ret = lasso_login_process_response_msg(LassoLogin_get(login_obj),
					 response_msg, remote_providerID);

  return (int_wrap(ret));
}
