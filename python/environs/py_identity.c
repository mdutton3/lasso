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

#include "py_identity.h"
#include "../xml/py_xml.h"


PyObject *LassoIdentity_wrap(LassoIdentity *identity) {
  PyObject *ret;

  if (identity == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) identity,
                                     (char *) "LassoIdentity *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *identity_new(PyObject *self, PyObject *args) {
  return (LassoIdentity_wrap(lasso_identity_new()));
}

PyObject *identity_new_from_dump(PyObject *self, PyObject *args) {
  LassoIdentity *identity;
  gchar *dump;

  if (CheckArgs(args, "S:identity_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:identity_new_from_dump", &dump))
      return NULL;
  }
  else return NULL;

  identity = lasso_identity_new_from_dump(dump);

  return (LassoIdentity_wrap(identity));
}

PyObject *identity_add_assertion(PyObject *self, PyObject *args){
  PyObject  *identity_obj, *assertion_obj;
  gchar     *remote_providerID;

  if (CheckArgs(args, "OSO:identity_add_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "OsO:identity_add_assertion", &identity_obj,
			 &remote_providerID, &assertion_obj))
      return NULL;
  }
  else return NULL;

  lasso_identity_add_assertion(LassoIdentity_get(identity_obj), remote_providerID,
			   LASSO_NODE(LassoAssertion_get(assertion_obj)));
/*   lasso_identity_add_assertion(LassoIdentity_get(identity_obj), remote_providerID, */
/* 			   LassoNode_get(assertion_obj)); */

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *identity_destroy(PyObject *self, PyObject *args) {
  PyObject *identity_obj;

  if (CheckArgs(args, "O:identity_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:identity_destroy",
			 &identity_obj))
      return NULL;
  }
  else return NULL;

  lasso_identity_destroy(LassoIdentity_get(identity_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *identity_dump(PyObject *self, PyObject *args) {
  PyObject  *identity_obj;
  gchar     *dump;

  if (CheckArgs(args, "O:identity_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "O:identity_dump", &identity_obj))
      return NULL;
  }
  else return NULL;

  dump = lasso_identity_dump(LassoIdentity_get(identity_obj));

  return (charPtrConst_wrap(dump));
}

PyObject *identity_get_assertion(PyObject *self, PyObject *args) {
  PyObject  *identity_obj;
  LassoNode *assertion_node;
  gchar     *remote_providerID;

  if (CheckArgs(args, "OS:identity_get_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:identity_get_assertion", &identity_obj,
			 &remote_providerID))
      return NULL;
  }
  else return NULL;

  assertion_node = lasso_identity_get_assertion(LassoIdentity_get(identity_obj),
						remote_providerID);

  return (LassoNode_wrap(assertion_node));
}

PyObject *identity_get_authentication_method(PyObject *self, PyObject *args) {
  PyObject *identity_obj;
  gchar    *remote_providerID;
  gchar    *authentication_method;

  if (CheckArgs(args, "Os:identity_get_authentication_method")) {
    if(!PyArg_ParseTuple(args, (char *) "Oz:identity_get_authentication_method",
			 &identity_obj, &remote_providerID))
      return NULL;
  }
  else return NULL;

  authentication_method = lasso_identity_get_authentication_method(LassoIdentity_get(identity_obj),
								   remote_providerID);

  return (charPtrConst_wrap(authentication_method));
}

PyObject *identity_get_next_assertion_remote_providerID(PyObject *self, PyObject *args) {
  PyObject  *identity_obj;
  gchar     *remote_providerID;

  if (CheckArgs(args, "O:identity_get_next_assertion_remote_providerID")) {
    if(!PyArg_ParseTuple(args, (char *) "O:identity_get_next_assertion_remote_providerID",
			 &identity_obj))
      return NULL;
  }
  else return NULL;

  remote_providerID = lasso_identity_get_next_assertion_remote_providerID(LassoIdentity_get(identity_obj));

  return (charPtrConst_wrap(remote_providerID));
}

PyObject *identity_remove_assertion(PyObject *self, PyObject *args) {
  PyObject  *identity_obj;
  gchar     *remote_providerID;
  int       code;

  if (CheckArgs(args, "OS:identity_remove_assertion")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:identity_remove_assertion", &identity_obj,
			 &remote_providerID))
      return NULL;
  }
  else return NULL;

  code = lasso_identity_remove_assertion(LassoIdentity_get(identity_obj), remote_providerID);

  return (int_wrap(code));
}
