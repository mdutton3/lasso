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
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lasso/id-wsf/wsf_profile.h>

struct _LassoWsfProfilePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_wsf_profile_build_request_msg(LassoWsfProfile *profile)
{
	profile->msg_url = NULL; /* FIXME : set SOAP url */
	profile->msg_body = lasso_node_export_to_soap(profile->request, /* FIXME : set keys */
						      NULL,
						      NULL);

	return 0;
}

gint
lasso_wsf_profile_build_response_msg(LassoWsfProfile *profile)
{
	profile->msg_url = NULL; /* FIXME : set SOAP url */
	profile->msg_body = lasso_node_export_to_soap(profile->response, /* FIXME : set keys */
						      NULL,
						      NULL);

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode, *t;
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(node);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(node);
	xmlNode *t;

	return 0;
}


/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);

	if (profile->private_data->dispose_has_run) {
		return;
	}
	profile->private_data->dispose_has_run = TRUE;

	debug("Profile object 0x%x disposed ...", profile);

	/* XXX unref reference counted objects */
	/* lasso_server_destroy(profile->server);
	lasso_identity_destroy(profile->identity);
	lasso_session_destroy(profile->session);

	lasso_node_destroy(profile->request);
	lasso_node_destroy(profile->response);
	*/

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(profile));
}

static void
finalize(GObject *object)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);

	debug("Profile object 0x%x finalized ...", object);

	g_free(profile->msg_url);
	g_free(profile->msg_body);

	g_free(profile->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsfProfile *profile)
{
	profile->private_data = g_new(LassoWsfProfilePrivate, 1);
	profile->private_data->dispose_has_run = FALSE;

	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
}

static void
class_init(LassoWsfProfileClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
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

gchar*
lasso_wsf_profile_dump(LassoWsfProfile *profile)
{
	return lasso_node_dump(LASSO_NODE(profile), NULL, 1);
}

