/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 * Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>

#include <lasso/id-ff/provider.h>

struct _LassoProviderPrivate
{
	gboolean dispose_has_run;
	GHashTable *SPDescriptor;
	GHashTable *IDPDescriptor;
};

static char *protocol_uris[] = {
	"http://projectliberty.org/profiles/fedterm",
	"http://projectliberty.org/profiles/nim",
	"http://projectliberty.org/profiles/rni",
	"http://projectliberty.org/profiles/slo",
	NULL /* none for single sign on */
};
static char *protocol_md_nodename[] = {
	"FederationTerminationNotificationProtocolProfile",
	"NameIdentifierMappingProtocolProfile",
	"RegisterNameIdentifierProtocolProfile",
	"SingleLogoutProtocolProfile",
	"SingleSignOnProtocolProfile"
};
static char *protocol_roles[] = { NULL, "sp", "idp"};
char *protocol_methods[] = {"", "", "", "", "", "-http", "-soap"};



/*****************************************************************************/
/* public methods */
/*****************************************************************************/

gchar*
lasso_provider_get_metadata_one(LassoProvider *provider, const char *name)
{
	GList *l;
	GHashTable *descriptor;

	descriptor = provider->private->SPDescriptor; /* default to SP */
	if (provider->role == LASSO_PROVIDER_ROLE_IDP)
		descriptor = provider->private->IDPDescriptor;

	l = g_hash_table_lookup(descriptor, name);
	if (l)
		return g_strdup(l->data);

	return NULL;
}

GList*
lasso_provider_get_metadata_list(LassoProvider *provider, const char *name)
{
	GHashTable *descriptor;

	descriptor = provider->private->SPDescriptor; /* default to SP */
	if (provider->role == LASSO_PROVIDER_ROLE_IDP)
		descriptor = provider->private->IDPDescriptor;

	return g_hash_table_lookup(descriptor, name);
}


lassoHttpMethod lasso_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, lassoMdProtocolType protocol_type)
{
	char *protocol_profile_prefix;
	GList *local_supported_profiles;
	GList *remote_supported_profiles;
	GList *t1, *t2;
	gboolean found;

	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP)
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP)
		provider->role = LASSO_PROVIDER_ROLE_SP;

	protocol_profile_prefix = g_strdup_printf("%s-%s",
			protocol_uris[protocol_type], protocol_roles[provider->role]);

	local_supported_profiles = lasso_provider_get_metadata_list(
			provider, protocol_md_nodename[protocol_type]);
	remote_supported_profiles = lasso_provider_get_metadata_list(
			remote_provider, protocol_md_nodename[protocol_type]);

	found = FALSE;
	t1 = local_supported_profiles;
	while (t1 && !found) {
		if (g_str_has_prefix(t1->data, protocol_profile_prefix)) {
			t2 = remote_supported_profiles;
			while (t2 && !found) {
				if (strcmp(t1->data, t2->data) == 0) {
					found = TRUE;
					break; /* avoid the g_list_next */
				}
				t2 = g_list_next(t2);
			}
		}
		t1 = g_list_next(t1);
	}
	g_free(protocol_profile_prefix);

	if (found) {
		if (g_str_has_suffix(t2->data, "http"))
			return LASSO_HTTP_METHOD_REDIRECT;
		if (g_str_has_suffix(t2->data, "soap"))
			return LASSO_HTTP_METHOD_SOAP;
		g_assert_not_reached();
	}

	return LASSO_HTTP_METHOD_NONE;
}

gboolean
lasso_provider_accept_http_method(LassoProvider *provider, LassoProvider *remote_provider,
		lassoMdProtocolType protocol_type, lassoHttpMethod http_method,
		gboolean initiate_profile)
{ 
	LassoProviderRole initiating_role;
	char *protocol_profile;

	initiating_role = remote_provider->role;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		provider->role = LASSO_PROVIDER_ROLE_SP;
	}
	if (initiate_profile)
		initiating_role = provider->role;

	protocol_profile = g_strdup_printf("%s-%s%s",
			protocol_uris[protocol_type],
			protocol_roles[initiating_role],
			protocol_methods[http_method+1]);

	if (lasso_provider_has_protocol_profile(provider,
				protocol_type, protocol_profile) == FALSE)
		return FALSE;

	if (lasso_provider_has_protocol_profile(remote_provider,
				protocol_type, protocol_profile) == FALSE)
		return FALSE;

	return TRUE;
}

gboolean
lasso_provider_has_protocol_profile(LassoProvider *provider,
		lassoMdProtocolType protocol_type, const char *protocol_profile)
{
	GList *supported;
	
	supported = lasso_provider_get_metadata_list(
			provider, protocol_md_nodename[protocol_type]);
	
	if (g_list_find_custom(supported, protocol_profile, (GCompareFunc)strcmp) == NULL)
		return FALSE;
	return TRUE;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
load_descriptor(xmlNode *xmlnode, GHashTable *descriptor)
{
	xmlNode *t;
	GList *elements;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		/* XXX: AssertionConsumerServiceURL nodes have attributes */
		elements = g_hash_table_lookup(descriptor, t->name);
		elements = g_list_append(elements, g_strdup(xmlNodeGetContent(t)));
		g_hash_table_insert(descriptor, g_strdup(t->name), elements);
		t = t->next;
	}
}

static void
add_descriptor_childnodes(gchar *key, GList *value, xmlNode *xmlnode)
{
	while (value) {
		xmlNewTextChild(xmlnode, NULL, key, value->data);
		value = g_list_next(value);
	}
}

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode, *t;
	LassoProvider *provider = LASSO_PROVIDER(node);
	char *roles[] = { "None", "SP", "IdP"};

	xmlnode = xmlNewNode(NULL, "Provider");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, "Version", "2");
	if (provider->role)
		xmlSetProp(xmlnode, "ProviderRole", roles[provider->role]);
	xmlSetProp(xmlnode, "ProviderID", provider->ProviderID);

	if (provider->public_key)
		xmlNewTextChild(xmlnode, NULL, "PublicKeyFilePath", provider->public_key);
	if (provider->ca_cert_chain)
		xmlNewTextChild(xmlnode, NULL, "CaCertChainFilePath", provider->ca_cert_chain);

	if (g_hash_table_size(provider->private->SPDescriptor)) {
		t = xmlNewTextChild(xmlnode, NULL, "SPDescriptor", NULL);
		g_hash_table_foreach(provider->private->SPDescriptor,
				(GHFunc)add_descriptor_childnodes, t);
	}

	if (g_hash_table_size(provider->private->IDPDescriptor)) {
		t = xmlNewTextChild(xmlnode, NULL, "IDPDescriptor", NULL);
		g_hash_table_foreach(provider->private->IDPDescriptor,
				(GHFunc)add_descriptor_childnodes, t);
	}
	
	
	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoProvider *provider = LASSO_PROVIDER(node);
	xmlNode *t;
	xmlChar *s;

	if (xmlnode == NULL)
		return -1;

	s = xmlGetProp(xmlnode, "ProviderRole");
	if (s && strcmp(s, "SP") == 0)
		provider->role = LASSO_PROVIDER_ROLE_SP;
	if (s && strcmp(s, "IdP") == 0)
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	if (s)
		xmlFree(s);

	provider->ProviderID = xmlGetProp(xmlnode, "ProviderID");

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "PublicKeyFilePath") == 0)
			provider->public_key = xmlNodeGetContent(t);
		if (strcmp(t->name, "CaCertChainFilePath") == 0)
			provider->ca_cert_chain = xmlNodeGetContent(t);
		if (strcmp(t->name, "SPDescriptor") == 0)
			load_descriptor(t, provider->private->SPDescriptor);
		if (strcmp(t->name, "IDPDescriptor") == 0)
			load_descriptor(t, provider->private->IDPDescriptor);
		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

	if (provider->private->dispose_has_run) {
		return;
	}
	provider->private->dispose_has_run = TRUE;

	debug("Provider object 0x%x disposed ...", provider);

	/* XXX: free hash tables (here or in finalize() below) ? */

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(provider));
}

static void
finalize(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

	debug("Provider object 0x%x finalized ...", provider);

	g_free(provider->public_key);
	g_free(provider->ca_cert_chain);
	g_free(provider->private);

	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(provider));
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoProvider *provider)
{
	provider->private = g_new (LassoProviderPrivate, 1);
	provider->private->dispose_has_run = FALSE;
	provider->role = LASSO_PROVIDER_ROLE_NONE;
	provider->public_key = NULL;
	provider->ca_cert_chain = NULL;
	provider->ProviderID = NULL;
	provider->private->IDPDescriptor = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);
	provider->private->SPDescriptor = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);
}

static void
class_init(LassoProviderClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_provider_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoProviderClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoProvider),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoProvider", &this_info, 0);
	}
	return this_type;
}

gboolean
lasso_provider_load_metadata(LassoProvider *provider, const gchar *metadata)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *node;

	doc = xmlParseFile(metadata);
	/* FIXME: lacking error checking */

	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "md", LASSO_METADATA_HREF);
	xpathObj = xmlXPathEvalExpression("/md:EntityDescriptor", xpathCtx);
	/* if empty: not a metadata file -> bails out */
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		return FALSE;
	}
	node = xpathObj->nodesetval->nodeTab[0];
	provider->ProviderID = xmlGetProp(node, "providerID");

	xpathObj = xmlXPathEvalExpression("md:EntityDescriptor/md:IDPDescriptor", xpathCtx);
	if (xpathObj && xpathObj->nodesetval->nodeNr == 1)
		load_descriptor(xpathObj->nodesetval->nodeTab[0], provider->private->IDPDescriptor);
	xmlXPathFreeObject(xpathObj);
	xpathObj = xmlXPathEvalExpression("md:EntityDescriptor/md:SPDescriptor", xpathCtx);
	if (xpathObj && xpathObj->nodesetval->nodeNr == 1)
		load_descriptor(xpathObj->nodesetval->nodeTab[0], provider->private->SPDescriptor);
	xmlXPathFreeObject(xpathObj);

	xmlFreeDoc(doc);
	xmlXPathFreeContext(xpathCtx);

	return TRUE;
}

LassoProvider*
lasso_provider_new(LassoProviderRole role, gchar *metadata, gchar *public_key, gchar *ca_cert_chain)
{
	LassoProvider *provider;

	provider = LASSO_PROVIDER(g_object_new(LASSO_TYPE_PROVIDER, NULL));
	provider->role = role;
	if (lasso_provider_load_metadata(provider, metadata) == FALSE) {
		/* XXX */
	}

	provider->public_key = g_strdup(public_key);
	provider->ca_cert_chain = g_strdup(ca_cert_chain);

	return provider;
}

LassoProvider*
lasso_provider_new_from_dump(const gchar *dump)
{
	LassoProvider *provider;
	xmlDoc *doc;

	provider = g_object_new(LASSO_TYPE_PROVIDER, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(provider), xmlDocGetRootElement(doc)); 

	return provider;
}

int lasso_provider_verify_signature(LassoProvider *provider,
		const char *message, const char *id_attr_name)
{
	return 0; /* XXX */
	
	if (message[0] == '<') {
		xmlDoc *doc;
		xmlNode *xmlnode, *sign, *x509data;
		xmlSecKeysMngr *keys_mngr = NULL;
		xmlSecDSigCtx *dsigCtx;
		lassoPemFileType public_key_file_type;

		doc = xmlParseMemory(message, strlen(message));
		xmlnode = xmlDocGetRootElement(doc);
		sign = xmlSecFindNode(xmlnode, xmlSecNodeSignature, xmlSecDSigNs);
		if (sign == NULL) {
			xmlFreeDoc(doc);
			return LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
		}

		x509data = xmlSecFindNode(xmlnode, xmlSecNodeX509Data, xmlSecDSigNs);
		if (x509data != NULL && provider->ca_cert_chain != NULL) {
			keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
					provider->ca_cert_chain);
			if (keys_mngr == NULL)
				return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
		}

		dsigCtx = xmlSecDSigCtxCreate(keys_mngr);
		if (keys_mngr == NULL) {
			if (provider->public_key) {
				public_key_file_type = lasso_get_pem_file_type(
						provider->public_key);
				if (public_key_file_type == LASSO_PEM_FILE_TYPE_CERT) {
					/* public_key_file is a certificate file
					 * => get public key in it */
					dsigCtx->signKey = lasso_get_public_key_from_pem_cert_file(
							provider->public_key);
				} else {
					/* load public key */
					dsigCtx->signKey = xmlSecCryptoAppKeyLoad(
							provider->public_key,
							xmlSecKeyDataFormatPem,
							NULL, NULL, NULL);
				}
			}
			if (dsigCtx->signKey == NULL) {
				return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
			}
		}

		if (xmlSecDSigCtxVerify(dsigCtx, sign) < 0) {
			return LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
		}
		if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
			return LASSO_DS_ERROR_INVALID_SIGNATURE;
		}

		return 0;
	}

	if (strchr(message, '&')) {
		return lasso_query_verify_signature(message, provider->public_key);
	}

	return -1;
}

