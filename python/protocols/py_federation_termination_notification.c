/* $Id$ 
 *
 * PyLasso -- Python bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
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

#include "py_federation_termination_notification.h"

PyObject *LassoFederationTerminationNotification_wrap(LassoFederationTerminationNotification *notification) {
  PyObject *ret;

  if (notification == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) notification,
                                     (char *) "LassoFederationTerminationNotification *", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *federation_termination_notification_new(PyObject *self, PyObject *args) {
  const xmlChar *providerID;
  const xmlChar *nameIdentifier;
  const xmlChar *nameQualifier = NULL;
  const xmlChar *format = NULL;

  LassoNode *notification;

  if (CheckArgs(args, "SSSS:federation_termination_notification_new")) {
    if(!PyArg_ParseTuple(args, (char *) "ssss:federation_termination_notification_new",
			 &providerID, &nameIdentifier,&nameQualifier, &format))
      return NULL;
  }
  else return NULL;

  notification = lasso_federation_termination_notification_new(providerID,
							       nameIdentifier,
							       nameQualifier,
							       format);

  return (LassoFederationTerminationNotification_wrap(LASSO_FEDERATION_TERMINATION_NOTIFICATION(notification)));
}

PyObject *federation_termination_notification_new_from_soap(PyObject *self, PyObject *args) {
  const xmlChar *soap_buffer;

  LassoNode     *notification;

  if (CheckArgs(args, "S:federation_termination_notification_new_from_soap")) {
    if(!PyArg_ParseTuple(args, (char *) "s:federation_termination_notification_new_from_soap",
			 &soap_buffer))
      return NULL;
  }
  else return NULL;

  notification = lasso_federation_termination_notification_new_from_soap(soap_buffer);

  return (LassoFederationTerminationNotification_wrap(LASSO_FEDERATION_TERMINATION_NOTIFICATION(notification)));
}

PyObject *federation_termination_notification_new_from_query(PyObject *self, PyObject *args) {
  const xmlChar *query;

  LassoNode     *notification;

  if (CheckArgs(args, "S:federation_termination_notification_new_from_query")) {
    if(!PyArg_ParseTuple(args, (char *) "s:federation_termination_notification_new_from_query",
			 &query))
      return NULL;
  }
  else return NULL;

  notification = lasso_federation_termination_notification_new_from_query(query);

  return (LassoFederationTerminationNotification_wrap(LASSO_FEDERATION_TERMINATION_NOTIFICATION(notification)));
}
