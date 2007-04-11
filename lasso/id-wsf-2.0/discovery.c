/* $Id: discovery.c,v 1.75 2007/01/03 23:35:17 Exp $
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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>

#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/saml_assertion.h>
#include <lasso/xml/saml_attribute_value.h>
//#include <lasso/xml/disco_modify.h>
#include <lasso/xml/ds_key_info.h>
#include <lasso/xml/ds_key_value.h>
#include <lasso/xml/ds_rsa_key_value.h>

#include <lasso/xml/id-wsf-2.0/disco_svc_md_register.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_metadata.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/provider.h>
#include <lasso/id-ff/providerprivate.h>

#include <lasso/id-wsf-2.0/discovery.h>
//#include <lasso/id-wsf/identity.h>
//#include <lasso/id-wsf/data_service.h>
//#include <lasso/id-wsf/personal_profile_service.h>
#include <lasso/id-wsf-2.0/wsf2_profile_private.h>

struct _LassoIdwsf2DiscoveryPrivate
{
	gboolean dispose_has_run;
	GList *new_entry_ids;
	char *security_mech_id;
};

/*****************************************************************************/
/* public methods */
/*****************************************************************************/


/**
 * lasso_discovery_destroy:
 * @discovery: a LassoDiscovery
 * 
 * Destroys LassoDiscovery objects created with lasso_discovery_new() or
 * lasso_discovery_new_from_dump().
 **/
void
lasso_idwsf2_discovery_destroy(LassoIdwsf2Discovery *discovery)
{
	g_object_unref(G_OBJECT(discovery));
}


/**
 * lasso_discovery_init_query
 * @discovery: a #LassoDiscovery
 *
 * Initializes a disco:Query message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_discovery_init_query(LassoIdwsf2Discovery *discovery, const gchar *security_mech_id)
{
	LassoIdwsf2DiscoQuery *query;

	query = lasso_idwsf2_disco_query_new();
	lasso_wsf2_profile_init_soap_request(LASSO_WSF2_PROFILE(discovery), LASSO_NODE(query));

	return 0;
}


gint
lasso_idwsf2_discovery_init_metadata_register(LassoIdwsf2Discovery *discovery,
	gchar *service_type, gchar *abstract, gchar *disco_provider_id)
{
	LassoDiscoSvcMDRegister *metadata_register;

	/* Get the providerId of this SP */
	LassoProvider *provider = LASSO_PROVIDER(LASSO_WSF2_PROFILE(discovery)->server);
	gchar *sp_provider_id = provider->ProviderID;

	/* Get a MetadataRegister node */
	metadata_register = lasso_disco_svc_md_register_new(
			service_type, abstract, sp_provider_id);

	if (metadata_register == NULL) {
		/* FIXME */
		return -1;
	}
	
	/* Create request with this xml node */
	lasso_wsf2_profile_init_soap_request(LASSO_WSF2_PROFILE(discovery),
			LASSO_NODE(metadata_register));

	/* Get the url of the idp where we must send the soap request */
	LASSO_WSF2_PROFILE(discovery)->msg_url = g_strdup(disco_provider_id);

	printf(lasso_node_dump(LASSO_NODE(metadata_register)));
	return 0;
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
	xmlNodeSetName(xmlnode, (xmlChar*)"Discovery");
	xmlSetProp(xmlnode, (xmlChar*)"DiscoveryDumpVersion", (xmlChar*)"2");

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
	LassoIdwsf2Discovery *discovery = LASSO_IDWSF2_DISCOVERY(object);

	if (discovery->private_data->dispose_has_run == TRUE)
		return;
	discovery->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoIdwsf2Discovery *discovery = LASSO_IDWSF2_DISCOVERY(object);
	g_free(discovery->private_data);
	discovery->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoIdwsf2Discovery *discovery)
{
	discovery->private_data = g_new0(LassoIdwsf2DiscoveryPrivate, 1);
	discovery->private_data->dispose_has_run = FALSE;
}

static void
class_init(LassoIdwsf2DiscoveryClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_idwsf2_discovery_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoIdwsf2DiscoveryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdwsf2Discovery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF2_PROFILE,
						   "LassoIdwsf2Discovery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_discovery_new:
 * @server: the #LassoServer
 *
 * Creates a new #LassoIdwsf2Discovery.
 *
 * Return value: a newly created #LassoIdwsf2Discovery object; or NULL if an error
 *      occured.
 **/
LassoIdwsf2Discovery*
lasso_idwsf2_discovery_new(LassoServer *server)
{
	LassoIdwsf2Discovery *discovery = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	discovery = g_object_new(LASSO_TYPE_IDWSF2_DISCOVERY, NULL);
	LASSO_WSF2_PROFILE(discovery)->server = g_object_ref(server);

	return discovery;
}
