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

#include "py_server.h"

PyObject *LassoServer_wrap(LassoServer *server) {
  PyObject *ret;

  if (server == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) server,
                                     (char *) "LassoServer *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *server_new(PyObject *self, PyObject *args) {
  LassoServer *server;
  gchar *metadata;
  gchar *public_key = NULL;
  gchar *private_key = NULL;
  gchar *certificate = NULL;
  guint  signature_method = 0;

  if (CheckArgs(args, "Ssssi:server_new")) {
    if(!PyArg_ParseTuple(args, (char *) "szzz|i:server_new",
			 &metadata, &public_key, &private_key, &certificate,
			 &signature_method))
      return NULL;
  }
  else return NULL;

  server = lasso_server_new(metadata, public_key, private_key,
			    certificate, signature_method);

  return (LassoServer_wrap(LASSO_SERVER(server)));
}

PyObject *server_new_from_dump(PyObject *self, PyObject *args) {
  LassoServer *server;
  gchar *dump;

  if (CheckArgs(args, "S:server_new_from_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "s:server_new_from_dump",
			 &dump))
      return NULL;
  }
  else return NULL;

  server = lasso_server_new_from_dump(dump);

  return (LassoServer_wrap(LASSO_SERVER(server)));
}

PyObject *server_add_provider(PyObject *self, PyObject *args) {
  PyObject *server_obj;
  gchar       *metadata;
  gchar       *public_key = NULL;
  gchar       *certificat = NULL;

  if (CheckArgs(args, "OSss:server_add_provider")) {
    if(!PyArg_ParseTuple(args, (char *) "Oszz:server_add_provider",
			 &server_obj, &metadata, &public_key, &certificat))
      return NULL;
  }
  else return NULL;
  
  lasso_server_add_provider(LassoServer_get(server_obj),
			    metadata, public_key, certificat);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *server_destroy(PyObject *self, PyObject *args) {
  PyObject *server_obj;

  if (CheckArgs(args, "O:server_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:server_destroy",
			 &server_obj))
      return NULL;
  }
  else return NULL;
  
  lasso_server_destroy(LassoServer_get(server_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *server_dump(PyObject *self, PyObject *args) {
  PyObject *server_obj;
  gchar *ret;

  if (CheckArgs(args, "O:server_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "O:server_dump",
			 &server_obj))
      return NULL;
  }
  else return NULL;
  
  ret = lasso_server_dump(LassoServer_get(server_obj));

  return (charPtrConst_wrap(ret));
}
