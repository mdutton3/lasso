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

PyObject *node_destroy(PyObject *self, PyObject *args) {
  PyObject *node_obj;

  if (CheckArgs(args, "O:node_destroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:node_destroy", &node_obj))
      return NULL;
  }
  else return NULL;

  lasso_node_destroy(LassoNode_get(node_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *node_dump(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlChar *encoding;
  int format;
  xmlChar *ret;

  if (CheckArgs(args, "OSI:node_dump")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:node_dump",
			 &node_obj, &encoding, &format))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_dump(LassoNode_get(node_obj), encoding, format);

  return (xmlCharPtr_wrap(ret));
}

PyObject *node_export(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlChar *ret;

  if (CheckArgs(args, "O:node_export")) {
    if(!PyArg_ParseTuple(args, (char *) "O:node_export", &node_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_export(LassoNode_get(node_obj));

  return (xmlCharPtr_wrap(ret));
}

PyObject *node_export_to_base64(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlChar *ret;

  if (CheckArgs(args, "O:node_export_to_base64")) {
    if(!PyArg_ParseTuple(args, (char *) "O:node_export_to_base64", &node_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_export_to_base64(LassoNode_get(node_obj));

  return (xmlCharPtr_wrap(ret));
}

PyObject *node_export_to_query(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  guint sign_method;
  const gchar *private_key_file;
  gchar *ret;

  if (CheckArgs(args, "Ois:node_export_to_query")) {
    if(!PyArg_ParseTuple(args, (char *) "Oiz:node_export_to_query",
			 &node_obj, &sign_method, &private_key_file))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_export_to_query(LassoNode_get(node_obj),
				   sign_method, private_key_file);

  return (charPtr_wrap(ret));
}

PyObject *node_export_to_soap(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  gchar *ret;

  if (CheckArgs(args, "O:node_export_to_soap")) {
    if(!PyArg_ParseTuple(args, (char *) "O:node_export_to_soap",
			 &node_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_export_to_soap(LassoNode_get(node_obj));

  return (xmlCharPtr_wrap(ret));
}

PyObject *node_get_attr_value(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *name;
  xmlChar *ret;

  if (CheckArgs(args, "OS:node_get_attr_value")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:node_get_attr_value",
			 &node_obj, &name))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_get_attr_value(LassoNode_get(node_obj), name);

  return (xmlCharPtr_wrap(ret));
}

PyObject *node_get_child(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *name, *href;
  LassoNode *ret;

  if (CheckArgs(args, "OSs:node_get_child")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:node_get_child",
			 &node_obj, &name, &href))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_get_child(LassoNode_get(node_obj), name, href);

  return (LassoNode_wrap(ret));
}

PyObject *node_get_content(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlChar *ret;

  if (CheckArgs(args, "O:node_get_content")) {
    if(!PyArg_ParseTuple(args, (char *) "O:node_get_content",
			 &node_obj))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_get_content(LassoNode_get(node_obj));

  return (xmlCharPtr_wrap(ret));
}

PyObject *node_verify_signature(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const gchar *certificate_file;
  gint ret;

  if (CheckArgs(args, "OS:node_verify_signature")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:node_verify_signature",
			 &node_obj, &certificate_file))
      return NULL;
  }
  else return NULL;

  ret = lasso_node_verify_signature(LassoNode_get(node_obj),
				    certificate_file);

  return (int_wrap(ret));
}
