/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
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

#include "../lassomod.h"

#include "py_xml.h"

PyObject *LassoNode_wrap(LassoNode *node) {
  PyObject *ret;

  if (node == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) node,
                                     (char *) "LassoNode *", NULL);
  return (ret);
}

/******************************************************************************/
/* LassoNode                                                                  */
/******************************************************************************/

PyObject *node_dump(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlChar *encoding;
  int format;

  if (CheckArgs(args, "OSI:node_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:node_dump",
			 &node_obj, &encoding, &format))
      return NULL;
  }
  else return NULL;

  lasso_node_dump(LassoNode_get(node_obj), encoding, format);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *node_unref(PyObject *self, PyObject *args) {
  PyObject *node_obj;

  if (CheckArgs(args, "O:node_unref")) {
    if(!PyArg_ParseTuple(args, (char *) "O:node_unref", &node_obj))
      return NULL;
  }
  else return NULL;

  /* FIXME: should used a fct lasso_node_unref() ??? */
  g_object_unref (G_OBJECT (LassoNode_get(node_obj)));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *node_url_encode(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  guint sign_method;
  const gchar *private_key_file;
  gchar *ret;

  if (CheckArgs(args, "OIS:node_unref")) {
    if(!PyArg_ParseTuple(args, (char *) "Ois:node_url_encode",
			 &node_obj, &sign_method, &private_key_file))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_url_encode(LassoNode_get(node_obj),
			      sign_method, private_key_file);

  return (charPtr_wrap(ret));
}
