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

#include "py_saml_name_identifier.h"

PyObject *LassoSamlNameIdentifier_wrap(LassoSamlNameIdentifier *node) {
  PyObject *ret;

  if (node == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) node,
                                     (char *) "LassoSamlNameIdentifier *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *saml_name_identifier_new(PyObject *self, PyObject *args) {
  xmlChar *content;
  LassoNode *node;

  if (CheckArgs(args, "S:saml_name_identifier_new")) {
    if(!PyArg_ParseTuple(args, (char *) "s:saml_name_identifier_new",
			 &content))
      return NULL;
  }
  else return NULL;

  node = lasso_saml_name_identifier_new(content);

  return (LassoSamlNameIdentifier_wrap(LASSO_SAML_NAME_IDENTIFIER(node)));
}

PyObject *saml_name_identifier_set_format(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *format;

  if (CheckArgs(args, "OS:saml_name_identifier_set_format")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:saml_name_identifier_set_format",
			 &node_obj, &format))
      return NULL;
  }
  else return NULL;

  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(node_obj),
					format);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *saml_name_identifier_set_nameQualifier(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *nameQualifier;

  if (CheckArgs(args, "OS:saml_name_identifier_set_nameQualifier")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:saml_name_identifier_set_nameQualifier",
			 &node_obj, &nameQualifier))
      return NULL;
  }
  else return NULL;

  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(node_obj),
					       nameQualifier);

  Py_INCREF(Py_None);
  return (Py_None);
}
