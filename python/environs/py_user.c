/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
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

#include "../lassomod.h"

#include "../xml/py_xml.h"

#include "py_user.h"

#include "../protocols/elements/py_assertion.h"

PyObject *LassoUser_wrap(LassoUser *user) {
  PyObject *ret;

  if (user == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) user,
                                     (char *) "LassoUser *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *user_new(PyObject *self, PyObject *args) {
  return (LassoUser_wrap(lasso_user_new()));
}

PyObject *user_new_from_dump(PyObject *self, PyObject *args) {
  LassoUser *user;
  gchar *dump;

  if (CheckArgs(args, "S:user_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:user_new_from_dump", &dump))
      return NULL;
  }
  else return NULL;

  user = lasso_user_new_from_dump(dump);

  return (LassoUser_wrap(user));
}

PyObject *user_add_assertion(PyObject *self, PyObject *args){
  PyObject  *user_obj;
  LassoNode *assertion_node;
  gchar     *remote_providerID;

  if (CheckArgs(args, "OSO:user_add_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "OsO:user_add_assertion", &user_obj, &remote_providerID, &assertion_node))
      return NULL;
  }
  else return NULL;

  lasso_user_add_assertion(LassoUser_get(user_obj), remote_providerID, LassoAssertion_get(assertion_node));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *user_destroy(PyObject *self, PyObject *args) {
  PyObject *user_obj;

  if (CheckArgs(args, "O:user_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:user_destroy",
			 &user_obj))
      return NULL;
  }
  else return NULL;

  lasso_user_destroy(LassoUser_get(user_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *user_dump(PyObject *self, PyObject *args) {
  PyObject  *user_obj;
  gchar     *dump;

  if (CheckArgs(args, "O:user_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "O:user_dump", &user_obj))
      return NULL;
  }
  else return NULL;

  dump = lasso_user_dump(LassoUser_get(user_obj));

  return (charPtrConst_wrap(dump));
}

PyObject *user_get_assertion(PyObject *self, PyObject *args) {
  PyObject  *user_obj;
  LassoNode *assertion_node;
  gchar     *remote_providerID;

  if (CheckArgs(args, "OS:user_get_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:user_get_assertion", &user_obj,
			 &remote_providerID))
      return NULL;
  }
  else return NULL;

  assertion_node = lasso_user_get_assertion(LassoUser_get(user_obj),
					    remote_providerID);

  return (LassoNode_wrap(assertion_node));
}

PyObject *user_get_authentication_method(PyObject *self, PyObject *args) {
  PyObject *user_obj;
  gchar    *remote_providerID;
  gchar    *authentication_method;

  if (CheckArgs(args, "Os:user_get_authentication_method")) {
    if(!PyArg_ParseTuple(args, (char *) "Oz:user_get_authentication_method",
			 &user_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

  authentication_method = lasso_user_get_authentication_method(LassoUser_get(user_obj),
							       remote_providerID);

  return (charPtrConst_wrap(authentication_method));
}

PyObject *user_get_next_assertion_remote_providerID(PyObject *self, PyObject *args) {
  PyObject  *user_obj;
  gchar     *remote_providerID;

  if (CheckArgs(args, "O:user_get_next_assertion_remote_providerID")) {
    if(!PyArg_ParseTuple(args, (char *) "O:user_get_next_assertion_remote_providerID",
			 &user_obj))
      return NULL;
  }
  else return NULL;

  remote_providerID = lasso_user_get_next_assertion_remote_providerID(LassoUser_get(user_obj));

  return (charPtrConst_wrap(remote_providerID));
}

PyObject *user_remove_assertion(PyObject *self, PyObject *args) {
  PyObject  *user_obj;
  gchar     *remote_providerID;
  int       code;

  if (CheckArgs(args, "OS:user_remove_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:user_remove_assertion", &user_obj,
			 &remote_providerID))
      return NULL;
  }
  else return NULL;

  code = lasso_user_remove_assertion(LassoUser_get(user_obj), remote_providerID);

  return (int_wrap(code));
}
