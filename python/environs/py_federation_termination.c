/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
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

#include "py_federation_termination.h"


PyObject *LassoFederationTermination_wrap(LassoFederationTermination *federation_termination) {
  PyObject *ret;

  if (federation_termination == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) federation_termination,
                                     (char *) "LassoFederationTermination *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *federation_termination_getattr(PyObject *self, PyObject *args) {
  PyObject *federation_termination_obj;
  LassoFederationTermination *federation_termination;
  const char *attr;

  if (CheckArgs(args, "OS:federation_termination_get_attr")) {
    if (!PyArg_ParseTuple(args, "Os:federation_termination_get_attr", &federation_termination_obj, &attr))
      return NULL;
  }
  else return NULL;

  federation_termination = LassoFederationTermination_get(federation_termination_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssss]", "user", "msg_url", "msg_body",
			 "msg_relayState");

  if (!strcmp(attr, "user"))
    return (LassoUser_wrap(LASSO_PROFILE_CONTEXT(federation_termination)->user));
  if (!strcmp(attr, "msg_url"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(federation_termination)->msg_url));
  if (!strcmp(attr, "msg_body"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(federation_termination)->msg_body));
  if (!strcmp(attr, "msg_relayState"))
    return (charPtrConst_wrap(LASSO_PROFILE_CONTEXT(federation_termination)->msg_relayState));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *federation_termination_new(PyObject *self, PyObject *args) {
  PyObject    *server_obj, *user_obj;
  LassoFederationTermination *federation_termination;
  gint         provider_type;

  if (CheckArgs(args, "OOI:federation_termination_new")) {
    if(!PyArg_ParseTuple(args, (char *) "OOi:federation_termination_new",
			 &server_obj, &user_obj, &provider_type))
      return NULL;
  }
  else return NULL;

  federation_termination = lasso_federation_termination_new(LassoServer_get(server_obj),
			    LassoUser_get(user_obj),

			    provider_type);

  return (LassoFederationTermination_wrap(federation_termination));
}

PyObject *federation_termination_build_notification_msg(PyObject *self, PyObject *args) {
  PyObject *federation_termination_obj;
  gint      codeError;

  if (CheckArgs(args, "O:federation_termination_build_notification_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "O:federation_termination_build_notification_msg",
			 &federation_termination_obj))
      return NULL;
  }
  else return NULL;

  codeError = lasso_federation_termination_build_notification_msg(LassoFederationTermination_get(federation_termination_obj));

  return(int_wrap(codeError));
}

PyObject *federation_termination_destroy(PyObject *self, PyObject *args){
  PyObject *federation_termination_obj;

  if (CheckArgs(args, "O:federation_termination_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:federation_termination_destroy",
			 &federation_termination_obj))
      return NULL;
  }
  else return NULL;

  lasso_federation_termination_destroy(LassoFederationTermination_get(federation_termination_obj));

  Py_INCREF(Py_None);
  return(Py_None);
}

PyObject *federation_termination_init_notification(PyObject *self, PyObject *args) {
  PyObject *federation_termination_obj;
  gchar    *remote_providerID;
  gint      codeError;

  if (CheckArgs(args, "Os:federation_termination_init_notification")) {
    if(!PyArg_ParseTuple(args, (char *) "Oz:federation_termination_init_notification",
			 &federation_termination_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

  codeError = lasso_federation_termination_init_notification(LassoFederationTermination_get(federation_termination_obj),
							     remote_providerID);

  return(int_wrap(codeError));
}

PyObject *federation_termination_process_notification_msg(PyObject *self, PyObject *args) {
  PyObject *federation_termination_obj;
  gchar    *notification_msg;
  gint      notification_method;
  gint      codeError;

  if (CheckArgs(args, "OSI:federation_termination_process_notification_msg")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:federation_termination_process_notification_msg",
			 &federation_termination_obj, &notification_msg, &notification_method))
      return NULL;
  }
  else return NULL;

  codeError = lasso_federation_termination_process_notification_msg(LassoFederationTermination_get(federation_termination_obj),
								    notification_msg, notification_method);

  return(int_wrap(codeError));
}

