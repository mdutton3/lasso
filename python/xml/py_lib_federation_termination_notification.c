/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *         Nicolas Clapies <nclapies@entrouvert.com>
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

#include "py_lib_federation_termination_notification.h"

PyObject *LassoLibFederationTerminationNotification_wrap(LassoLibFederationTerminationNotification *notification) {
  PyObject *ret;

  if (notification == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) notification,
                                     (char *) "LassoLibFederationTerminationNotification *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *lib_federation_termination_notification_new(PyObject *self, PyObject *args) {
  LassoNode *node;

  node = lasso_lib_federation_termination_notification_new();

  return (LassoLibFederationTerminationNotification_wrap(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(node)));
}

PyObject *lib_federation_termination_notification_set_consent(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *consent;

  if (CheckArgs(args, "OS:lib_federation_termination_notification_set_consent")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:lib_federation_termination_notification_set_consent",
			 &node_obj, &consent))
      return NULL;
  }
  else return NULL;

  lasso_lib_federation_termination_notification_set_consent(LassoLibFederationTerminationNotification_get(node_obj),
							    consent);

  Py_INCREF(Py_None);
  return (Py_None);
}
