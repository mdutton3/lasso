/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more You.
 * 
 * details should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lasso/id-wsf/personal_profile_service.h>
#include <lasso/xml/dst_data.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>

struct _LassoPersonalProfileServicePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_personal_profile_service_init_query(LassoPersonalProfileService *pp,
					  LassoDiscoResourceOffering *ResourceOffering,
					  const char *Select)
{
  LassoDstQueryItem *QueryItem;
  LassoWsfProfile *profile;
  LassoAbstractService *service;

  profile = LASSO_WSF_PROFILE(pp);
  service = LASSO_ABSTRACT_SERVICE(pp);

  QueryItem = lasso_dst_query_item_new(Select);
  
  profile->request = LASSO_NODE(lasso_dst_query_new(QueryItem));
  LASSO_DST_QUERY(profile->request)->prefixServiceType = LASSO_PP_PREFIX;
  LASSO_DST_QUERY(profile->request)->hrefServiceType = LASSO_PP_HREF;

  /* set ResourceID (encrypted or not) */
  if (ResourceOffering != NULL) {
	  service->ResourceOffering = ResourceOffering;
	  LASSO_DST_QUERY(profile->request)->ResourceID = \
		  g_strdup(ResourceOffering->ResourceID);
	  LASSO_DST_QUERY(profile->request)->EncryptedResourceID = \
		  g_strdup(ResourceOffering->EncryptedResourceID);
  }

  return 0;
}

gint
lasso_personal_profile_service_add_data(LassoPersonalProfileService *pp, LassoDstData *data)
{
	LassoWsfProfile *profile;
	LassoDstQueryResponse *response;

	profile = LASSO_WSF_PROFILE(pp);
	response = LASSO_DST_QUERY_RESPONSE(profile->response);

	response->Data = g_list_append(response->Data, (gpointer)data);

	return 0;
}

gint
lasso_personal_profile_service_process_request_msg(LassoPersonalProfileService *pp,
						   const char *query_soap_msg)
{
	LassoDstQuery *query;
	LassoDstQueryItem *query_item;
	LassoDstQueryResponse *query_response;
	LassoWsfProfile *profile;
	LassoUtilityStatus *status;

	profile = LASSO_WSF_PROFILE(pp);

	query = g_object_new(LASSO_TYPE_DST_QUERY, NULL);
	lasso_node_init_from_message(LASSO_NODE(query), query_soap_msg);

	/* get ResourceID / EncryptedResourceID */
	if (query->ResourceID != NULL) {
		LASSO_ABSTRACT_SERVICE(pp)->ResourceID = g_strdup(query->ResourceID);
		LASSO_ABSTRACT_SERVICE(pp)->is_encrypted = FALSE;
	}
	else {
		LASSO_ABSTRACT_SERVICE(pp)->ResourceID = g_strdup(query->EncryptedResourceID);
		LASSO_ABSTRACT_SERVICE(pp)->is_encrypted = TRUE;
	}
	/* get QueryItems */
	LASSO_ABSTRACT_SERVICE(pp)->QueryItem = query->QueryItem;

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	LASSO_WSF_PROFILE(pp)->response = LASSO_NODE(lasso_dst_query_response_new(status));
	LASSO_DST_QUERY_RESPONSE(profile->response)->prefixServiceType = LASSO_PP_PREFIX;
	LASSO_DST_QUERY_RESPONSE(profile->response)->hrefServiceType = LASSO_PP_HREF;

	return 0;
}

gint
lasso_personal_profile_service_process_response_msg(LassoPersonalProfileService *pp,
						    const char *query_response_soap_msg)
{
	LassoDstQueryResponse *query_response;
	GList *Data;

	query_response = g_object_new(LASSO_TYPE_DST_QUERY_RESPONSE, NULL);
	lasso_node_init_from_message(LASSO_NODE(query_response), query_response_soap_msg);

	LASSO_WSF_PROFILE(pp)->response = LASSO_NODE(query_response);

	LASSO_ABSTRACT_SERVICE(pp)->Data = query_response->Data;

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoPersonalProfileServiceClass *parent_class = NULL;

/*****************************************************************************/
/* overridden parent class methods                                            */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoPersonalProfileService *pp = LASSO_PERSONAL_PROFILE_SERVICE(object);

	if (pp->private_data->dispose_has_run) {
		return;
	}
	pp->private_data->dispose_has_run = TRUE;

	debug("Profile object 0x%x disposed ...", pp);

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(pp));
}

static void
finalize(GObject *object)
{
	LassoPersonalProfileService *pp = LASSO_PERSONAL_PROFILE_SERVICE(object);

	debug("LassoPersonalProfileService object 0x%x finalized ...", object);

	g_free(pp->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoPersonalProfileService *pp)
{
	pp->private_data = g_new(LassoPersonalProfileServicePrivate, 1);
	pp->private_data->dispose_has_run = FALSE;

}

static void
class_init(LassoPersonalProfileServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_personal_profile_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoPersonalProfileServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoPersonalProfileService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_ABSTRACT_SERVICE,
				"LassoPersonalProfileService", &this_info, 0);
	}
	return this_type;
}

LassoPersonalProfileService*
lasso_personal_profile_service_new(LassoServer *server)
{
	LassoPersonalProfileService *pp = NULL;

	pp = g_object_new(LASSO_TYPE_PERSONAL_PROFILE_SERVICE, NULL);

	return pp;
}
