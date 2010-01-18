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
#include "lib_authn_response_envelope.h"

/**
 * SECTION:lib_authn_response_envelope
 * @short_description: &lt;lib:AuthnResponseEnvelope&gt;
 *
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AuthnResponse", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibAuthnResponseEnvelope, AuthnResponse), NULL, NULL, NULL},
	{ "AssertionConsumerServiceURL", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnResponseEnvelope, AssertionConsumerServiceURL), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibAuthnResponseEnvelopeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnResponseEnvelope");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_authn_response_envelope_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthnResponseEnvelopeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnResponseEnvelope),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibAuthnResponseEnvelope", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_authn_response_envelope_new:
 * @response: the #LassoLibAuthnResponse to envelop
 * @assertionConsumerServiceURL: assertion consumer service URL on the service
 *      provider
 *
 * Creates a new #LassoLibAuthnResponseEnvelope object and initializes it with
 * the parameters.
 *
 * Return value: a newly created #LassoLibAuthnResponseEnvelope object
 **/
LassoLibAuthnResponseEnvelope*
lasso_lib_authn_response_envelope_new(LassoLibAuthnResponse *response,
		char *assertionConsumerServiceURL)
{
	LassoLibAuthnResponseEnvelope *envelope;

	envelope = g_object_new(LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE, NULL);
	if (response) {
		envelope->AuthnResponse = response;
		envelope->AssertionConsumerServiceURL = g_strdup(assertionConsumerServiceURL);
	}

	return envelope;
}
