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
    if(!PyArg_ParseTuple(args, (char *) "O|Os:login_new_from_dump", &server_obj,
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
