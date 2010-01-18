/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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

#include "private.h"
#include "soap_binding.h"

#define find_node_type_in_list(iter, check) \
	{\
		while (iter && ! check(iter->data)) \
			iter = iter->next;\
	}

/**
 * lasso_soap_binding_get_provider:
 * @envelope: a #LassoSoapEnvelope
 *
 * Look up the sb:Provider header in the SOAP message envelope.
 *
 * Return value: NULL if no Provider element is present in the header of the SOAP
 * envelope. If found it returns a reference you do not own.
 */
LassoSoapBindingProvider*
lasso_soap_binding_get_provider(LassoSoapEnvelope *envelope) {
	g_return_val_if_fail(envelope, NULL);

	if (envelope->Header) {
		GList *iter = envelope->Header->Other;
		find_node_type_in_list(iter, LASSO_IS_SOAP_BINDING_PROVIDER);
		if (iter) {
			return LASSO_SOAP_BINDING_PROVIDER(iter->data);
		}
	}
	return NULL;
}

/**
 * lasso_soap_binding_get_correlation:
 * @envelope: a #LassoSoapEnvelope
 *
 * Look up the sb:Correlation header in the SOAP message envelope.
 *
 * Return value: NULL if no Correlation element is present in the header of the
 * SOAP envelope. If found it returns a reference you do not own.
 */
LassoSoapBindingCorrelation*
lasso_soap_binding_get_correlation(LassoSoapEnvelope *envelope) {
	g_return_val_if_fail(envelope, NULL);

	if (envelope->Header) {
		GList *iter = envelope->Header->Other;
		find_node_type_in_list(iter, LASSO_IS_SOAP_BINDING_CORRELATION);
		if (iter) {
			return LASSO_SOAP_BINDING_CORRELATION(iter->data);
		}
	}
	return NULL;
}
