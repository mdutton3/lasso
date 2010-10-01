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

#include "server.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "../id-ff/server.h"
#include "../id-ff/serverprivate.h"
#include "../xml/id-wsf-2.0/disco_svc_metadata.h"
#include "../xml/id-wsf-2.0/disco_service_context.h"
#include <libxml/tree.h>

gint
lasso_server_add_svc_metadata(LassoServer *server, LassoIdWsf2DiscoSvcMetadata *metadata)
{

	g_return_val_if_fail(LASSO_IS_SERVER(server), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCO_SVC_METADATA(metadata),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	server->private_data->svc_metadatas = g_list_append(
		server->private_data->svc_metadatas, g_object_ref(metadata));

	return 0;
}


/**
 * lasso_server_get_svc_metadatas:
 * @server: a #LassoServer object
 *
 * Return value:(element-type LassoIdWsf2DiscoSvcMetadata)(transfer none): a list of #LassoIdWsf2DiscoSvcMetadata
 */
const GList *
lasso_server_get_svc_metadatas(LassoServer *server)
{
	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	return server->private_data->svc_metadatas;
}


/**
 * lasso_server_get_svc_metadatas_with_id_and_type:
 * @server: a #LassoServer object
 * @svcMDIDs:(allow-none): a list of service metadata IDs
 * @service_type:(allow-none): a service type identifier
 *
 * Return value:(element-type LassoIdWsf2DiscoSvcMetadata)(transfer full): a list of #LassoIdWsf2DiscoSvcMetadata
 */
GList *
lasso_server_get_svc_metadatas_with_id_and_type(LassoServer *server, GList *svcMDIDs,
	const gchar *service_type)
{
	gchar *svcMDID;
	LassoIdWsf2DiscoSvcMetadata *md;
	GList *result = NULL;
	GList *i;
	GList *j;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
	g_return_val_if_fail(service_type != NULL, NULL);

	for (i = g_list_first(server->private_data->svc_metadatas); i != NULL; i = g_list_next(i)) {
		md = LASSO_IDWSF2_DISCO_SVC_METADATA(i->data);
		/* FIXME: this assumes there is one and only one service
		 * context, and service type, this should be fixed to iterate
		 * properly on the GList */
		if (md->ServiceContext == NULL || strcmp((char*)(LASSO_IDWSF2_DISCO_SERVICE_CONTEXT(
				md->ServiceContext->data)->ServiceType)->data, service_type) != 0) {
			continue;
		}
		if (svcMDIDs == NULL) {
			/* If no svcMDID is given, return all the metadatas with given */
			/* service type */
			result = g_list_append(result, g_object_ref(md));
		} else {
			for (j = g_list_first(svcMDIDs); j != NULL; j = g_list_next(j)) {
				svcMDID = (gchar *)(j->data);
				if (strcmp(svcMDID, md->svcMDID) == 0) {
					result = g_list_append(result, g_object_ref(md));
				}
			}
		}
	}

	return result;
}

void
lasso_server_init_id_wsf20_svcmds(LassoServer *server, xmlNode *t)
{
	xmlNode *t2 = t->children;

	if (strcmp((char*)t->name, "SvcMDs") == 0) {
		while (t2) {
			LassoIdWsf2DiscoSvcMetadata *svcMD;
			if (t2->type != XML_ELEMENT_NODE) {
				t2 = t2->next;
				continue;
			}
			svcMD = lasso_idwsf2_disco_svc_metadata_new();
			LASSO_NODE_GET_CLASS(svcMD)->init_from_xml(LASSO_NODE(svcMD), t2);
			server->private_data->svc_metadatas = g_list_append(
				server->private_data->svc_metadatas, svcMD);
			t2 = t2->next;
		}
	}
}

static void
add_childnode_from_list(LassoNode *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

void
lasso_server_dump_id_wsf20_svcmds(LassoServer *server, xmlNode *xmlnode)
{
	/* Service Metadatas (SvcMD) */
	if (server->private_data->svc_metadatas != NULL) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"SvcMDs", NULL);
		g_list_foreach(server->private_data->svc_metadatas,
				(GFunc)add_childnode_from_list, t);
	}
}
