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

#include "py_session.h"
#include "../xml/py_xml.h"

PyObject *LassoSession_wrap(LassoSession *session) {
  PyObject *ret;

  if (session == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) session,
                                     (char *) "LassoSession *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *session_new(PyObject *self, PyObject *args) {
  return (LassoSession_wrap(lasso_session_new()));
}

PyObject *session_new_from_dump(PyObject *self, PyObject *args) {
  LassoSession *session;
  gchar *dump;

  if (CheckArgs(args, "S:session_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:session_new_from_dump", &dump))
      return NULL;
  }
  else return NULL;

  session = lasso_session_new_from_dump(dump);

  return (LassoSession_wrap(session));
}

PyObject *session_add_assertion(PyObject *self, PyObject *args){
  PyObject  *session_obj, *assertion_obj;
  gchar     *remote_providerID;

  if (CheckArgs(args, "OSO:session_add_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "OsO:session_add_assertion", &session_obj,
			 &remote_providerID, &assertion_obj))
      return NULL;
  }
  else return NULL;

  lasso_session_add_assertion(LassoSession_get(session_obj), remote_providerID,
			      LassoNode_get(assertion_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *session_destroy(PyObject *self, PyObject *args) {
  PyObject *session_obj;

  if (CheckArgs(args, "O:session_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:session_destroy",
			 &session_obj))
      return NULL;
  }
  else return NULL;

  lasso_session_destroy(LassoSession_get(session_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *session_dump(PyObject *self, PyObject *args) {
  PyObject  *session_obj;
  gchar     *dump;

  if (CheckArgs(args, "O:session_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "O:session_dump", &session_obj))
      return NULL;
  }
  else return NULL;

  dump = lasso_session_dump(LassoSession_get(session_obj));

  return (charPtrConst_wrap(dump));
}

PyObject *session_get_assertion(PyObject *self, PyObject *args) {
  PyObject  *session_obj;
  LassoNode *assertion_node;
  gchar     *remote_providerID;

  if (CheckArgs(args, "OS:session_get_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:session_get_assertion", &session_obj,
			 &remote_providerID))
      return NULL;
  }
  else return NULL;

  assertion_node = lasso_session_get_assertion(LassoSession_get(session_obj),
					       remote_providerID);

  return (LassoNode_wrap(assertion_node));
}

PyObject *session_get_authentication_method(PyObject *self, PyObject *args) {
  PyObject *session_obj;
  gchar    *remote_providerID;
  gchar    *authentication_method;

  if (CheckArgs(args, "Os:session_get_authentication_method")) {
    if(!PyArg_ParseTuple(args, (char *) "Oz:session_get_authentication_method",
			 &session_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

  authentication_method = lasso_session_get_authentication_method(LassoSession_get(session_obj),
								  remote_providerID);

  return (charPtrConst_wrap(authentication_method));
}

PyObject *session_get_next_assertion_remote_providerID(PyObject *self, PyObject *args) {
  PyObject  *session_obj;
  gchar     *remote_providerID;

  if (CheckArgs(args, "O:session_get_next_assertion_remote_providerID")) {
    if(!PyArg_ParseTuple(args, (char *) "O:session_get_next_assertion_remote_providerID",
			 &session_obj))
      return NULL;
  }
  else return NULL;

  remote_providerID = lasso_session_get_next_assertion_remote_providerID(LassoSession_get(session_obj));

  return (charPtrConst_wrap(remote_providerID));
}

PyObject *session_remove_assertion(PyObject *self, PyObject *args) {
  PyObject  *session_obj;
  gchar     *remote_providerID;
  int       code;

  if (CheckArgs(args, "OS:session_remove_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:session_remove_assertion", &session_obj,
			 &remote_providerID))
      return NULL;
  }
  else return NULL;

  code = lasso_session_remove_assertion(LassoSession_get(session_obj),
					remote_providerID);

  return (int_wrap(code));
}
