/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <lasso/id-wsf/wsf_profile.h>
#include <lasso/xml/disco_modify.h>
#include <lasso/xml/soap_binding_correlation.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoSoapEnvelope*
lasso_wsf_profile_build_soap_envelope(const char *refToMessageId)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;
	LassoSoapBindingCorrelation *correlation;
	gchar *messageId, *timestamp;

	/* set Body */
	body = lasso_soap_body_new();
	envelope = lasso_soap_envelope_new(body);

	/* set Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	/* set Correlation */
	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
	if (refToMessageId != NULL)
		correlation->refToMessageID = g_strdup(refToMessageId);
	header->Other = g_list_append(header->Other, correlation);

	return envelope;
}

gint
lasso_wsf_profile_build_request_msg(LassoWsfProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* FIXME : set keys */
       	if (LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request) == TRUE) {
		profile->msg_body = lasso_node_dump(LASSO_NODE(profile->soap_envelope_request));
	}
	else if (LASSO_IS_NODE(profile->request) == TRUE) {
		profile->msg_body = lasso_node_export_to_soap(profile->request);
	}

	return 0;
}

gint
lasso_wsf_profile_build_response_msg(LassoWsfProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* FIXME : set keys */
       	if (LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_response) == TRUE) {
		profile->msg_body = lasso_node_dump(LASSO_NODE(profile->soap_envelope_response));
	}
	else if (LASSO_IS_NODE(profile->response) == TRUE) {
		profile->msg_body = lasso_node_export_to_soap(profile->response);
	}

	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsfProfile *profile)
{
	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->soap_envelope_request = NULL;
	profile->soap_envelope_response = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
}

static void
class_init(LassoWsfProfileClass *klass)
{

}

GType
lasso_wsf_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoWsfProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsfProfile),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsfProfile", &this_info, 0);
	}
	return this_type;
}

LassoWsfProfile*
lasso_wsf_profile_new(LassoServer *server)
{
	LassoWsfProfile *profile = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	profile = g_object_new(LASSO_TYPE_WSF_PROFILE, NULL);

	return profile;
}
