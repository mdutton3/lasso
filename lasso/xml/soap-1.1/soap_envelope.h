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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_SOAP_ENVELOPE_H__
#define __LASSO_SOAP_ENVELOPE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "soap_body.h"
#include "soap_header.h"

#define LASSO_TYPE_SOAP_ENVELOPE (lasso_soap_envelope_get_type())
#define LASSO_SOAP_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SOAP_ENVELOPE, LassoSoapEnvelope))
#define LASSO_SOAP_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SOAP_ENVELOPE, LassoSoapEnvelopeClass))
#define LASSO_IS_SOAP_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SOAP_ENVELOPE))
#define LASSO_IS_SOAP_ENVELOPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SOAP_ENVELOPE))
#define LASSO_SOAP_ENVELOPE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SOAP_ENVELOPE, LassoSoapEnvelopeClass))

typedef struct _LassoSoapEnvelope LassoSoapEnvelope;
typedef struct _LassoSoapEnvelopeClass LassoSoapEnvelopeClass;

struct _LassoSoapEnvelope {
	LassoNode parent;

	LassoSoapHeader *Header;
	LassoSoapBody *Body;
};

struct _LassoSoapEnvelopeClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_soap_envelope_get_type(void);

LASSO_EXPORT LassoSoapEnvelope* lasso_soap_envelope_new(LassoSoapBody *body);

LASSO_EXPORT LassoSoapEnvelope* lasso_soap_envelope_new_from_message(const gchar *message);

LASSO_EXPORT LassoSoapEnvelope* lasso_soap_envelope_new_full(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SOAP_ENVELOPE_H__ */
