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

#include <lasso/id-ff/federation.h>

struct _LassoFederationPrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* static methods/functions                                                  */
/*****************************************************************************/

static LassoSamlNameIdentifier*
lasso_federation_build_nameIdentifier(const gchar *nameQualifier,
				      const gchar *format,
				      const gchar *content)
{
	LassoSamlNameIdentifier *nameIdentifier;

	if (content == NULL) {
		nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(lasso_saml_name_identifier_new());
		nameIdentifier->content = lasso_build_unique_id(32);
	} else {
		nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(lasso_saml_name_identifier_new());
		nameIdentifier->content = g_strdup(content);
	}
	nameIdentifier->NameQualifier = g_strdup(nameQualifier);
	nameIdentifier->Format = g_strdup(format);

	return nameIdentifier;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_federation_build_local_nameIdentifier(LassoFederation *federation,
					    const gchar     *nameQualifier,
					    const gchar     *format,
					    const gchar     *content)
{
	federation->local_nameIdentifier = lasso_federation_build_nameIdentifier(
			nameQualifier, format, content);
}

void
lasso_federation_set_local_name_identifier(LassoFederation *federation,
		LassoSamlNameIdentifier *name_identifier)
{
	if (federation->local_nameIdentifier)
		g_object_unref(federation->local_nameIdentifier);
	federation->local_nameIdentifier = g_object_ref(name_identifier);
}
void
lasso_federation_set_remote_name_identifier(LassoFederation *federation,
		LassoSamlNameIdentifier *name_identifier)
{
	if (federation->remote_nameIdentifier)
		g_object_unref(federation->remote_nameIdentifier);
	federation->remote_nameIdentifier = g_object_ref(name_identifier);
}

void
lasso_federation_destroy(LassoFederation *federation)
{
	g_object_unref(G_OBJECT(federation));
}

gboolean
lasso_federation_verify_nameIdentifier(LassoFederation *federation,
				       LassoSamlNameIdentifier *nameIdentifier)
{
	char *s;
	/* XXX: verify_nameIdentifier only checks content; what about Format
	 * and NameQualifier ? */

	g_return_val_if_fail(LASSO_IS_FEDERATION(federation), FALSE);
	g_return_val_if_fail(LASSO_IS_NODE(nameIdentifier), FALSE);

	/* verify local name identifier */
	if (federation->local_nameIdentifier != NULL) {
		s = federation->local_nameIdentifier->content;
		if (strcmp(s, nameIdentifier->content) == 0) {
			return TRUE;
		}
	}

	/* verify remote name identifier */
	if (federation->remote_nameIdentifier != NULL) {
		s = federation->remote_nameIdentifier->content;
		if (strcmp(s, nameIdentifier->content) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode, *t;
	LassoFederation *federation = LASSO_FEDERATION(node);

	xmlnode = xmlNewNode(NULL, "Federation");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, "Version", "2");

	if (federation->remote_providerID)
		xmlSetProp(xmlnode, "RemoteProviderID", federation->remote_providerID);

	if (federation->local_nameIdentifier) {
		t = xmlNewTextChild(xmlnode, NULL, "LocalNameIdentifier", NULL);
		xmlAddChild(t, lasso_node_get_xmlNode(
					LASSO_NODE(federation->local_nameIdentifier)));
	}

	if (federation->remote_nameIdentifier) {
		t = xmlNewTextChild(xmlnode, NULL, "RemoteNameIdentifier", NULL);
		xmlAddChild(t, lasso_node_get_xmlNode(
					LASSO_NODE(federation->remote_nameIdentifier)));
	}

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoFederation *federation = LASSO_FEDERATION(node);
	xmlNode *t, *n;

	federation->remote_providerID = xmlGetProp(xmlnode, "RemoteProviderID");
	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		if (strcmp(t->name, "LocalNameIdentifier") == 0) {
			n = t->children;
			while (n && n->type != XML_ELEMENT_NODE) n = n->next;
			if (n) {
				federation->local_nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(
						lasso_node_new_from_xmlNode(n));
			}
		}

		if (strcmp(t->name, "RemoteNameIdentifier") == 0) {
			n = t->children;
			while (n && n->type != XML_ELEMENT_NODE) n = n->next;
			if (n) {
				federation->remote_nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(
						lasso_node_new_from_xmlNode(n));
			}
		}
		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoFederation *federation = LASSO_FEDERATION(object);
	if (federation->private_data->dispose_has_run) {
		return;
	}
	federation->private_data->dispose_has_run = TRUE;

	debug("Federation object 0x%x disposed ...", federation);

	/* unref reference counted objects */
	lasso_node_destroy(LASSO_NODE(federation->local_nameIdentifier));
	lasso_node_destroy(LASSO_NODE(federation->remote_nameIdentifier));

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoFederation *federation = LASSO_FEDERATION(object);
	debug("Federation object 0x%x finalized ...", federation);

	g_free(federation->remote_providerID);
	g_free(federation->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoFederation *federation)
{
	federation->private_data = g_new(LassoFederationPrivate, 1);
	federation->private_data->dispose_has_run = FALSE;

	federation->remote_providerID  = NULL;
	federation->local_nameIdentifier  = NULL;
	federation->remote_nameIdentifier = NULL;
}

static void
class_init(LassoFederationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_federation_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoFederationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoFederation),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoFederation", &this_info, 0);
	}
	return this_type;
}

LassoFederation*
lasso_federation_new(gchar *remote_providerID)
{
	LassoFederation *federation;

	g_return_val_if_fail(remote_providerID != NULL, NULL);

	federation = LASSO_FEDERATION(g_object_new(LASSO_TYPE_FEDERATION, NULL));
	federation->remote_providerID = g_strdup(remote_providerID);

	return federation;
}

