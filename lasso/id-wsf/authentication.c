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

#include <lasso/id-wsf/authentication.h>
#include <lasso/xml/sa_sasl_request.h>
#include <lasso/xml/sa_sasl_response.h>

gint
lasso_authentication_init_request(LassoAuthentication *authentication,
				  LassoDiscoDescription *description,
				  const gchar *mechanism)
{
	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(mechanism != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	LASSO_WSF_PROFILE(authentication)->request = \
		LASSO_NODE(lasso_sa_sasl_request_new(mechanism));

	if (description->Endpoint != NULL) {
		LASSO_WSF_PROFILE(authentication)->msg_url = g_strdup(description->Endpoint);
	}
	else if (description->WsdlURI != NULL) {
		/* TODO: get Endpoint at WsdlURI */
	}

	return 0;
}

gint
lasso_authentication_process_request_msg(LassoAuthentication *authentication,
					 const gchar *soap_msg)
{
	LassoSaSaslRequest *request;
	LassoSaSaslResponse *response;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(soap_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	request = lasso_sa_sasl_request_new_from_message(soap_msg);
	LASSO_WSF_PROFILE(authentication)->request = LASSO_NODE(request);

	status = lasso_utility_status_new(LASSO_SA_STATUS_CODE_OK);
	response = lasso_sa_sasl_response_new(status);
	LASSO_WSF_PROFILE(authentication)->response = LASSO_NODE(response);

	return 0;
}

gint
lasso_authentication_process_response_msg(LassoAuthentication *authentication,
					  const gchar *soap_msg)
{
	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(soap_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	return 0;
}


struct _LassoAuthenticationPrivate
{
	gboolean dispose_has_run;
};

void
lasso_authentication_destroy(LassoAuthentication *authentication)
{
	g_object_unref(G_OBJECT(authentication));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, "Authentication");
	xmlSetProp(xmlnode, "AuthenticationDumpVersion", "2");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	return 0;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoAuthentication *authentication = LASSO_AUTHENTICATION(object);

	if (authentication->private_data->dispose_has_run == TRUE)
		return;
	authentication->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoAuthentication *authentication = LASSO_AUTHENTICATION(object);
	g_free(authentication->private_data);
	authentication->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoAuthentication *authentication)
{
	authentication->private_data = g_new(LassoAuthenticationPrivate, 1);
	authentication->private_data->dispose_has_run = FALSE;
}

static void
class_init(LassoAuthenticationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_authentication_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoAuthenticationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoAuthentication),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
						   "LassoAuthentication", &this_info, 0);
	}
	return this_type;
}

LassoAuthentication*
lasso_authentication_new(LassoServer *server)
{
	LassoAuthentication *authentication = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	authentication = g_object_new(LASSO_TYPE_AUTHENTICATION, NULL);
	LASSO_WSF_PROFILE(authentication)->server = server;

	return authentication;
}
