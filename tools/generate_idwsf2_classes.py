#! /usr/bin/env python

import os
import re
import xml.dom.minidom
import string
import sys

full_constructors = {
    'disco_svc_metadata': (
    '''LASSO_EXPORT LassoIdWsf2DiscoSvcMetadata* lasso_idwsf2_disco_svc_metadata_new_full(
\t\tconst gchar *service_type, const gchar *abstract,
\t\tconst gchar *provider_id, const gchar *soap_endpoint);''',
    '''
LassoIdWsf2DiscoSvcMetadata*
lasso_idwsf2_disco_svc_metadata_new_full(const gchar *service_type, const gchar *abstract,
\t\tconst gchar *provider_id, const gchar *soap_endpoint)
{
\tLassoIdWsf2DiscoSvcMetadata *metadata;
\tLassoIdWsf2DiscoEndpointContext *endpoint_context;

\tmetadata = lasso_idwsf2_disco_svc_metadata_new();

\tmetadata->Abstract = g_strdup(abstract);
\tmetadata->ProviderID = g_strdup(provider_id);

\tendpoint_context = lasso_idwsf2_disco_endpoint_context_new_full(soap_endpoint);
\tmetadata->ServiceContext = g_list_append(NULL,
\t\tlasso_idwsf2_disco_service_context_new_full(service_type, endpoint_context));

\treturn metadata;
}
'''),

    'disco_svc_md_register' : (
    '''LASSO_EXPORT LassoIdWsf2DiscoSvcMDRegister* lasso_idwsf2_disco_svc_md_register_new_full(
\t\tconst gchar *service_type, const gchar *abstract,
\t\tconst gchar *provider_id, const gchar *soap_endpoint);''',
    '''
LassoIdWsf2DiscoSvcMDRegister*
lasso_idwsf2_disco_svc_md_register_new_full(const gchar *service_type, const gchar *abstract,
\t\tconst gchar *provider_id, const gchar *soap_endpoint)
{
\tLassoIdWsf2DiscoSvcMDRegister *metadata_register;
\tLassoIdWsf2DiscoSvcMetadata *metadata;

\tmetadata_register = lasso_idwsf2_disco_svc_md_register_new();
\tmetadata = lasso_idwsf2_disco_svc_metadata_new_full(service_type, abstract, provider_id,
\t\t\tsoap_endpoint);
\tmetadata_register->SvcMD = g_list_append(
\t\t\tmetadata_register->SvcMD, metadata);

\treturn metadata_register;
}'''),

    'dstref_query_item': (
    '''LASSO_EXPORT LassoIdWsf2DstRefQueryItem* lasso_idwsf2_dstref_query_item_new_full(
\t\tconst gchar *item_xpath, const gchar *item_id);''',
    '''
LassoIdWsf2DstRefQueryItem*
lasso_idwsf2_dstref_query_item_new_full(const gchar *item_xpath, const gchar *item_id)
{
\tLassoIdWsf2DstRefResultQuery *item_result_query = LASSO_IDWSF2_DSTREF_RESULT_QUERY(
\t\tlasso_idwsf2_dstref_query_item_new());
\tLassoIdWsf2DstResultQueryBase *item_result_query_base = LASSO_IDWSF2_DST_RESULT_QUERY_BASE(
\t\titem_result_query);

\titem_result_query->Select = g_strdup(item_xpath);
\titem_result_query_base->itemID = g_strdup(item_id);

\treturn LASSO_IDWSF2_DSTREF_QUERY_ITEM(item_result_query);
}'''),

    'sb2_redirect_request': (
    '''LASSO_EXPORT LassoIdWsf2Sb2RedirectRequest* lasso_idwsf2_sb2_redirect_request_new_full(
\t\tconst gchar *redirect_url);''',
    '''
LassoIdWsf2Sb2RedirectRequest*
lasso_idwsf2_sb2_redirect_request_new_full(const gchar *redirect_url)
{
\tLassoIdWsf2Sb2RedirectRequest *request;

\trequest = lasso_idwsf2_sb2_redirect_request_new();
\trequest->redirectURL = g_strdup(redirect_url);

\treturn request;
}'''),

    'disco_endpoint_context': (
    '''LASSO_EXPORT LassoIdWsf2DiscoEndpointContext* lasso_idwsf2_disco_endpoint_context_new_full(
\t\tconst gchar *address);''',
    '''
LassoIdWsf2DiscoEndpointContext*
lasso_idwsf2_disco_endpoint_context_new_full(const gchar *address)
{
\tLassoIdWsf2DiscoEndpointContext *context;
\tLassoIdWsf2SbfFramework *sbf_framework;

\tcontext = lasso_idwsf2_disco_endpoint_context_new();

\tcontext->Address = g_list_append(NULL, g_strdup(address));
\tsbf_framework = lasso_idwsf2_sbf_framework_new();
\tsbf_framework->version = g_strdup("2.0");
\tcontext->Framework = g_list_append(NULL, sbf_framework);

\treturn context;
}'''),

    'disco_service_context': (
    '''LASSO_EXPORT LassoIdWsf2DiscoServiceContext* lasso_idwsf2_disco_service_context_new_full(
\t\tconst gchar *serviceType, LassoIdWsf2DiscoEndpointContext *endpointContext);''',
    '''
LassoIdWsf2DiscoServiceContext*
lasso_idwsf2_disco_service_context_new_full(
\t\tconst gchar *serviceType, LassoIdWsf2DiscoEndpointContext *endpointContext)
{
\tLassoIdWsf2DiscoServiceContext *context;

\tcontext = lasso_idwsf2_disco_service_context_new();

\tcontext->ServiceType = g_list_append(NULL, g_strdup(serviceType));
\tcontext->EndpointContext = g_list_append(NULL, g_object_ref(endpointContext));

\treturn context;
}'''),

}

for d in ('id-wsf-2.0', 'ws', 'swig-id-wsf-2.0', 'swig-ws'):
    if not os.path.exists(d):
        os.mkdir(d)

def rep(s):
    return s.group(0)[0] + '_' + s.group(1).lower()


def get_by_name_and_attribute(dom, name, attribute_name, attribute_value):
    elems = dom.getElementsByTagName(name)
    result = []
    for elem in elems:
        if not elem.attributes.has_key(attribute_name):
            continue
        if elem.attributes.get(attribute_name).value == attribute_value:
            result.append(elem)

    return result


def get_str_classes():
    str_classes = ['ID', 'string', 'anyURI', 'dateTime', 'NCName', 'text-child',
            'NMTOKEN', 'NMTOKENS', 'token', 'normalizedString', 'IDREF', 'QName']
    str_classes += ['xs:'+x for x in str_classes]
    str_classes += ['saml:' + x for x in string_classes] + string_classes[:]
    lu_classes = ['IDType', 'IDReferenceType']
    str_classes += lu_classes + ['lu:'+x for x in lu_classes] + ['util:'+x for x in lu_classes]
    str_classes += ['tns:RelationshipTypeOpenEnum']
    str_classes += ['wsu:AttributedDateTime']
    return str_classes


class LassoClass:
    has_ds_signature = False
    has_custom_ns = False
    node_set_name = None

    def generate_header(self):
        s = []
        s.append("""/* $Id: %(file_name)s.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_%(category_upper)s%(file_name_upper)s_H__
#define __LASSO_%(category_upper)s%(file_name_upper)s_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
""" % self.__dict__)
        includes = {}
        for elem in self.elements:
            if elem[1] in string_classes:
                continue
            includes[elem[1]] = True

        if self.base_class_name != 'Node':
            if self.prefix == 'samlp2':
                includes['samlp:' + self.base_class_name[6:]] = True
            elif self.prefix == 'saml2':
                includes['saml:' + self.base_class_name[5:]] = True
            else:
                b_pref = self.base_prefix
                if not b_pref:
                    b_pref = self.prefix

                if b_pref in ('lu', 'util'):
                    includes['util:' + self.base_class_name[10:]] = True
                elif b_pref == 'ps':
                    includes['ps:' + self.base_class_name[8:]] = True
                elif b_pref == 'is':
                    includes['is:' + self.base_class_name[8:]] = True
                elif b_pref == 'subs':
                    includes['subs:' + self.base_class_name[10:]] = True
                elif b_pref == 'ims':
                    includes['ims:' + self.base_class_name[9:]] = True
                elif b_pref == 'dst':
                    includes['dst:' + self.base_class_name[9:]] = True
                elif b_pref == 'subsref':
                    includes['subsref:' + self.base_class_name[13:]] = True
                elif b_pref == 'dstref':
                    includes['dstref:' + self.base_class_name[12:]] = True
                elif b_pref == 'wsa':
                    includes['wsa:' + self.base_class_name[6:]] = True
                elif b_pref == 'tns':
                    includes['wsa:' + self.base_class_name[6:]] = True
                else:
                    print b_pref, self.base_prefix, self.base_class_name
                    raise 'XXX'

        s.append('#include <lasso/xml/xml.h>')

        for inc in includes.keys():
            if ':' in inc:
                ns, name = inc.split(':')[-2:]
                if ns == 'xs':
                    continue
                if ns == 'lu':
                    ns = 'util'
                if ns == 'tns':
                    ns = 'wsa'
                try:
                    if ns.startswith('ws') and not self.prefix.startswith('ws'):
                        s.append('#include <lasso/xml/ws/%s.h>' % classes[ns][name].file_name)
                    elif ns == 'samlp':
                        samlp_header = 'samlp2_' + re.sub(r'[a-z]([A-Z])', rep, name).lower()
                        s.append('#include <lasso/xml/saml-2.0/%s.h>' % samlp_header)
                    else:
                        s.append('#include "%s.h"' % classes[ns][name].file_name)
                except KeyError:
                    print >> sys.stderr, 'W: missing', ns, name
                    if self.name == 'DataResponseBase':
                        print classes[ns].keys()
                        raise 'toot'
                    pass
            else:
                try:
                    s.append('#include "%s.h"' % classes[self.prefix][inc].file_name)
                except KeyError:
                    pass

        # extra headers
        if self.name == 'ServiceContext':
            s.append('#include "disco_endpoint_context.h"')

        if self.name in ('Advice', 'Evidence'):
            s.append("""
#ifndef __LASSO_SAML2_ASSERTION_H__
/* to avoid circular inclusion of saml2_assertion.h */
typedef struct _LassoSaml2Assertion LassoSaml2Assertion;
#endif
""")

        if len(self.prefix_cap) + len(self.file_name_upper) < 33:
            s.append("""\n#define LASSO_TYPE_%(category_upper)s%(file_name_upper)s (lasso_%(category)s%(file_name)s_get_type())""" % self.__dict__)
        else:
            s.append("""\n#define LASSO_TYPE_%(category_upper)s%(file_name_upper)s \\\n\t(lasso_%(category)s%(file_name)s_get_type())""" % self.__dict__)

        s.append("""#define LASSO_%(category_upper)s%(file_name_upper)s(obj) \\
\t(G_TYPE_CHECK_INSTANCE_CAST((obj), \\
\t\tLASSO_TYPE_%(category_upper)s%(file_name_upper)s, \\
\t\tLasso%(prefix_cap)s%(name)s))
#define LASSO_%(category_upper)s%(file_name_upper)s_CLASS(klass) \\
\t(G_TYPE_CHECK_CLASS_CAST((klass), \\
\t\tLASSO_TYPE_%(category_upper)s%(file_name_upper)s, \\
\t\tLasso%(prefix_cap)s%(name)sClass))
#define LASSO_IS_%(category_upper)s%(file_name_upper)s(obj) \\
\t(G_TYPE_CHECK_INSTANCE_TYPE((obj), \\
\t\tLASSO_TYPE_%(category_upper)s%(file_name_upper)s))
#define LASSO_IS_%(category_upper)s%(file_name_upper)s_CLASS(klass) \\
\t(G_TYPE_CHECK_CLASS_TYPE ((klass), \\
\t\tLASSO_TYPE_%(category_upper)s%(file_name_upper)s))
#define LASSO_%(category_upper)s%(file_name_upper)s_GET_CLASS(o) \\
\t(G_TYPE_INSTANCE_GET_CLASS ((o), \\
\t\tLASSO_TYPE_%(category_upper)s%(file_name_upper)s, \\
\t\tLasso%(prefix_cap)s%(name)sClass))
""" % self.__dict__)

        if len(self.prefix_cap) + len(self.name) > 30:
            s.append("""
typedef struct _Lasso%(prefix_cap)s%(name)s \\
\tLasso%(prefix_cap)s%(name)s;
typedef struct _Lasso%(prefix_cap)s%(name)sClass \\
\tLasso%(prefix_cap)s%(name)sClass;
""" % self.__dict__)
        else:
            s.append("""
typedef struct _Lasso%(prefix_cap)s%(name)s Lasso%(prefix_cap)s%(name)s;
typedef struct _Lasso%(prefix_cap)s%(name)sClass Lasso%(prefix_cap)s%(name)sClass;
""" % self.__dict__)



        s.append("""
struct _Lasso%(prefix_cap)s%(name)s {""" % self.__dict__)
        s.append("\tLasso%s parent;\n" % self.base_class_name)

        s.append('\t/*< public >*/')
        if self.elements:
            s.append('\t/* elements */')
        for elem in self.elements:
            name, type = elem[:2]
            if type in get_str_classes():
                type = 'char'
                name = '*'+name
            elif type in ['text-child-int']:
                type = 'int'
            elif type == 'GList':
                name = '*'+name
            else:
                type = ref_to_class_name(type)
                name = '*'+name
            s.append('\t%s %s;' % (type, name))

            if type == 'GList':
                if elem[2] == 'xmlNode':
                    s[-1] = s[-1] + ' /* of xmlNode* */'
                else:
                    t = ref_to_class_name(elem[2])
                    if not 'XXX' in t:
                        s[-1] = s[-1] + ' /* of %s */' % t

        if self.attributes:
            s.append('\t/* attributes */')
        for elem in self.attributes:
            name, type = elem[:2]
            if type.startswith('xs:'):
                type = type[3:]
            if name in ('signed', ): # reserved keywords
                name = name + '_'
            if type == 'boolean':
                type = 'gboolean'
            elif type in ('unsignedShort', 'integer', 'nonNegativeInteger'):
                type = 'int'
            elif type == 'any':
                type = 'GHashTable'
                name = '*attributes'
            else:
                type = 'char'
                name = '*'+name
            s.append('\t%s %s;' % (type, name))

        if self.has_ds_signature:
            s.append('\t/*< private >*/')
            s.append("""\t/* ds:Signature stuffs */
\tLassoSignatureType sign_type;
\tLassoSignatureMethod sign_method;
\tchar *private_key_file;
\tchar *certificate_file;
""")
        if self.has_custom_ns:
            s.append('''
\t/*< private >*/
\tchar *prefixServiceType;
\tchar *hrefServiceType;''')

        s.append('};\n')

        s.append("""
struct _Lasso%(prefix_cap)s%(name)sClass {
\tLasso%(base_class_name)sClass parent;
};

LASSO_EXPORT GType lasso_%(category)s%(file_name)s_get_type(void);
LASSO_EXPORT Lasso%(prefix_cap)s%(name)s* lasso_%(category)s%(file_name)s_new(void);
""" % self.__dict__)

        if ('content', 'text-child') in self.elements:
            s.append('LASSO_EXPORT Lasso%(prefix_cap)s%(name)s* lasso_%(category)s%(file_name)s_new_with_string(const char *content);' % self.__dict__)

        if ('text-child-int',) in self.elements:
            s.append('LASSO_EXPORT Lasso%(prefix_cap)s%(name)s* lasso_%(category)s%(file_name)s_new_with_int(int content);' % self.__dict__)

        if full_constructors.has_key(self.file_name):
            s.append(full_constructors.get(self.file_name)[0])

        s.append("""

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_%(category_upper)s%(file_name_upper)s_H__ */
""" % self.__dict__)

        return '\n'.join(s)

    def generate_source(self):
        s = []
        s.append("""/* $Id: %(file_name)s.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
""" % self.__dict__)

        if self.has_ds_signature:
            s.append("""
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
""")

        s.append('#include "%s.h"' % self.file_name)

        # extra headers
        if self.name == 'EndpointContext':
            s.append('#include "sbf_framework.h"');
        elif self.name == 'SvcMDRegister':
            s.append('#include "disco_svc_metadata.h"')
        elif self.name == 'SvcMetadata':
            s.append('#include "disco_endpoint_context.h"')
            s.append('#include "disco_service_context.h"')


        s.append("""
/*
 * Schema fragment (%s):
 *
%s
 */""" % (self.schema_filename, self.schema_fragment))

        s.append("""
/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

""")

        s.append("static struct XmlSnippet schema_snippets[] = {")

        for elem in self.elements:
            name, type = elem[:2]
            if type == 'text-child':
                snippet_type = 'SNIPPET_TEXT_CHILD'
            elif type == 'text-child-int':
                snippet_type = 'SNIPPET_TEXT_CHILD | SNIPPET_INTEGER'
            elif type in get_str_classes():
                snippet_type = 'SNIPPET_CONTENT'
            elif type == 'GList':
                if elem[2] == 'xmlNode':
                    snippet_type = 'SNIPPET_LIST_XMLNODES'
                elif elem[2] in get_str_classes():
                    snippet_type = 'SNIPPET_LIST_CONTENT'
                else:
                    snippet_type = 'SNIPPET_LIST_NODES'
            else:
                snippet_type = 'SNIPPET_NODE'
                if name == 'any':
                    snippet_type += ' | SNIPPET_ANY'

            varname = name

            if type in get_str_classes():
                auto_detect = True
            else:
                if type == 'GList':
                    type = elem[2]
                if type == 'xmlNode':
                    name = ''
                    auto_detect = True
                else:
                    type = ref_to_class_name(type)
                    if type == 'LassoNode':
                        name = ''
                        snippet_type += ' | SNIPPET_ANY'
                        auto_detect = True
                    elif classes.has_key(name):
                        auto_detect = True
                    else:
                        if 'XXX' in type or type.endswith('Abstract') or name == 'any':
                            auto_detect = True
                        else:
                            auto_detect = False

            if auto_detect:
                s.append('\t{ "%s", %s,\n\t\tG_STRUCT_OFFSET(Lasso%s%s, %s) },' % (
                        name, snippet_type, self.prefix_cap, self.name, varname))
            else:
                s.append('\t{ "%s", %s,\n\t\tG_STRUCT_OFFSET(Lasso%s%s, %s),\n\t\t"%s" },' % (
                        name, snippet_type, self.prefix_cap, self.name, name, type))

        id_name = 'XXX'
        for elem in self.attributes:
            name, type = elem[:2]
            if type.startswith('xs:'):
                type = type[3:]
            if type == 'ID':
                id_name = name
            if type in get_str_classes():
                snippet_type = 'SNIPPET_ATTRIBUTE'
            elif type in ('unsignedShort', 'nonNegativeInteger', 'integer'):
                snippet_type = 'SNIPPET_ATTRIBUTE | SNIPPET_INTEGER'
            elif type == 'boolean':
                snippet_type = 'SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN'
            elif type == 'any':
                snippet_type = 'SNIPPET_ATTRIBUTE | SNIPPET_ANY'
            else:
                raise 'unknown type: %r' % type
            if len(elem) == 3:
                optional = elem[2]
                if optional:
                    if type == 'nonNegativeInteger':
                        snippet_type += ' | SNIPPET_OPTIONAL_NEG'
                    else:
                        snippet_type += ' | SNIPPET_OPTIONAL'
            varname = name
            if type == 'any':
                varname = 'attributes'
            if varname in ('signed', ): # reserved keywords
                varname = varname + '_'
            s.append('\t{ "%s", %s,\n\t\tG_STRUCT_OFFSET(Lasso%s%s, %s) },' % (
                    name, snippet_type, self.prefix_cap, self.name, varname))

        if self.has_ds_signature:
            if id_name == 'XXX':
                s.append('\t{ "Signature", SNIPPET_SIGNATURE  },')
            else:
                s.append('\t{ "Signature", SNIPPET_SIGNATURE,\n\t\tG_STRUCT_OFFSET(Lasso%s%s, %s) },' % (
                        self.prefix_cap, self.name, id_name))

            s.append("""
\t/* hidden fields; used in lasso dumps */
\t{ "SignType", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
\t\tG_STRUCT_OFFSET(Lasso%(prefix_cap)s%(name)s, sign_type) },
\t{ "SignMethod", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
\t\tG_STRUCT_OFFSET(Lasso%(prefix_cap)s%(name)s, sign_method) },
\t{ "PrivateKeyFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
\t\tG_STRUCT_OFFSET(Lasso%(prefix_cap)s%(name)s, private_key_file) },
\t{ "CertificateFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
\t\tG_STRUCT_OFFSET(Lasso%(prefix_cap)s%(name)s, certificate_file) },
""" % self.__dict__)

        s.append("\t{NULL, 0, 0}\n};")

        s.append("""
static LassoNodeClass *parent_class = NULL;
""")

        if self.has_custom_ns:
            s.append('''
static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
\txmlNode *xmlnode;

\txmlnode = parent_class->get_xmlNode(node, lasso_dump);
\txml_insure_namespace(xmlnode, NULL, TRUE,
\t\t\tLASSO_%(category_upper)s%(file_name_upper)s(node)->hrefServiceType,
\t\t\tLASSO_%(category_upper)s%(file_name_upper)s(node)->prefixServiceType);

\treturn xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
\tLasso%(prefix_cap)s%(name)s *object = LASSO_%(category_upper)s%(file_name_upper)s(node);
\tint res;

\tres = parent_class->init_from_xml(node, xmlnode);
\tif (res != 0) {
\t\treturn res;
\t}

\tobject->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
\tobject->prefixServiceType = lasso_get_prefix_for_idwsf2_dst_service_href(
\t\t\tobject->hrefServiceType);
\tif (object->prefixServiceType == NULL) {
\t\t/* XXX: what to do here ? */
\t}

\treturn 0;
}
''' % self.__dict__)

        has_build_query = False
        if self.base_class_name == 'Samlp2RequestAbstract' or ( # two levels deep
                classes.has_key(self.base_class_name) and \
                classes[self.base_class_name].base_class_name == 'Samlp2RequestAbstract'):
            has_build_query = True
            qs_name = 'SAMLRequest'
        elif self.prefix == 'samlp2' and self.name.endswith('Response'):
            has_build_query = True
            qs_name = 'SAMLResponse'
        elif self.base_class_name == 'Samlp2StatusResponse':
            has_build_query = True
            qs_name = 'SAMLResponse'

        if self.name in ('ArtifactResolve', 'ArtifactResponse'):
            has_build_query = False

        if has_build_query:
            s.append("""
static gchar*
build_query(LassoNode *node)
{
\tchar *ret, *deflated_message;

\tdeflated_message = lasso_node_build_deflated_query(node);
\tret = g_strdup_printf("%s=%%s", deflated_message);
\t/* XXX: must support RelayState (which profiles?) */
\tg_free(deflated_message);
\treturn ret;
}
""" % qs_name)
        has_init_from_query = False
        if has_build_query:
            has_init_from_query = True
            s.append("""
static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
\tgboolean rc;
\tchar *relay_state = NULL;
\trc = lasso_node_init_from_saml2_query_fields(node, query_fields, &relay_state);
\tif (rc && relay_state != NULL) {
\t\t/* XXX: support RelayState? */
\t}
\treturn rc;
}
""")

        has_get_xml_node = False
        if self.has_ds_signature and id_name != 'XXX':
            # XXX: no id name for InteractionStatement -> no signature possible ?
            has_get_xml_node = True
            self.id_name = id_name
            s.append("""

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
\tLasso%(prefix_cap)s%(name)s *request = LASSO_%(category_upper)s%(file_name_upper)s(node);
\txmlNode *xmlnode;
\tint rc;
\t
\txmlnode = parent_class->get_xmlNode(node, lasso_dump);

\tif (lasso_dump == FALSE && request->sign_type) {
\t\trc = lasso_sign_node(xmlnode, "%(id_name)s", request->%(id_name)s,
\t\t\t\trequest->private_key_file, request->certificate_file);
\t\t/* signature may have failed; what to do ? */
\t}

\treturn xmlnode;
}
""" % self.__dict__)


        s.append("""
/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(Lasso%s%s *node)
{""" % (self.prefix_cap, self.name))

        for elem in self.elements + self.attributes:
            name, type = elem[:2]
            if name in ('signed', ): # reserved keywords
                name = name + '_'
            if type.startswith('xs:'):
                type = type[3:]

            if type in ('unsignedShort', 'integer', 'text-child-int'):
                s.append('\tnode->%s = 0;' % name)
            elif type == 'nonNegativeInteger':
                s.append('\tnode->%s = -1;' % name)
            elif type == 'boolean':
                s.append('\tnode->%s = FALSE;' % name)
            elif type == 'any' and elem in self.attributes:
                s.append('''\tnode->attributes = g_hash_table_new_full(
\t\tg_str_hash, g_str_equal, g_free, g_free);''')
            else:
                s.append('\tnode->%s = NULL;' % name)

        if self.has_ds_signature:
            s.append('\tnode->sign_type = LASSO_SIGNATURE_TYPE_NONE;')

        if self.has_custom_ns:
            s.append('\tnode->prefixServiceType = NULL;')
            s.append('\tnode->hrefServiceType = NULL;')

        s.append("""}

static void
class_init(Lasso%s%sClass *klass)
{
\tLassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

\tparent_class = g_type_class_peek_parent(klass);""" % (self.prefix_cap, self.name))
        if self.has_custom_ns:
            s.append('\tnclass->get_xmlNode = get_xmlNode;')
            s.append('\tnclass->init_from_xml = init_from_xml;')
        if has_build_query:
            s.append('\tnclass->build_query = build_query;')
        if has_init_from_query:
            s.append('\tnclass->init_from_query = init_from_query;')
        if has_get_xml_node:
            s.append('\tnclass->get_xmlNode = get_xmlNode;')
        if self.prefix == 'saml2':
            string_constant = 'SAML2_ASSERTION'
        elif self.prefix == 'samlp2':
            string_constant = 'SAML2_PROTOCOL'
        elif self.prefix == 'disco':
            string_constant = 'IDWSF2_DISCO'
        elif self.prefix == 'util':
            string_constant = 'IDWSF2_UTIL'
        elif self.prefix == 'dst':
            string_constant = 'IDWSF2_DST'
        elif self.prefix == 'dstref':
            string_constant = 'IDWSF2_DSTREF'
        elif self.prefix == 'sec':
            string_constant = 'IDWSF2_SEC'
        elif self.prefix == 'ims':
            string_constant = 'IDWSF2_IMS'
        elif self.prefix == 'subs':
            string_constant = 'IDWSF2_SUBS'
        elif self.prefix == 'subsref':
            string_constant = 'IDWSF2_SUBSREF'
        elif self.prefix == 'ps':
            string_constant = 'IDWSF2_PS'
        elif self.prefix == 'is':
            string_constant = 'IDWSF2_IS'
        elif self.prefix == 'sbf':
            string_constant = 'IDWSF2_SBF'
        elif self.prefix == 'sb2':
            string_constant = 'IDWSF2_SB2'
        elif self.prefix == 'wsa':
            string_constant = 'WSA'
        elif self.prefix == 'wsu':
            string_constant = 'WSUTIL1'
        elif self.prefix == 'wsse':
            string_constant = 'WSSE1'
        else:
            raise 'missing constant for %s' % self.prefix

        if not self.node_set_name:
            self.node_set_name = self.name
        s.append("""\tnclass->node_data = g_new0(LassoNodeClassData, 1);
\tlasso_node_class_set_nodename(nclass, "%s");
\tlasso_node_class_set_ns(nclass, LASSO_%s_HREF, LASSO_%s_PREFIX);
\tlasso_node_class_add_snippets(nclass, schema_snippets);""" % (
            self.node_set_name, string_constant, string_constant))

        if self.has_ds_signature:
            s.append("""
\tnclass->node_data->sign_type_offset = G_STRUCT_OFFSET(
\t\t\tLasso%(prefix_cap)s%(name)s, sign_type);
\tnclass->node_data->sign_method_offset = G_STRUCT_OFFSET(
\t\t\tLasso%(prefix_cap)s%(name)s, sign_method);""" % self.__dict__)

        s.append("""}

GType
lasso_%(category)s%(file_name)s_get_type()
{
\tstatic GType this_type = 0;

\tif (!this_type) {
\t\tstatic const GTypeInfo this_info = {
\t\t\tsizeof (Lasso%(prefix_cap)s%(name)sClass),
\t\t\tNULL,
\t\t\tNULL,
\t\t\t(GClassInitFunc) class_init,
\t\t\tNULL,
\t\t\tNULL,
\t\t\tsizeof(Lasso%(prefix_cap)s%(name)s),
\t\t\t0,
\t\t\t(GInstanceInitFunc) instance_init,
\t\t};

\t\tthis_type = g_type_register_static(%(base_class_type)s,
\t\t\t\t"Lasso%(prefix_cap)s%(name)s", &this_info, 0);
\t}
\treturn this_type;
}

/**
 * lasso_%(category)s%(file_name)s_new:
 *
 * Creates a new #Lasso%(prefix_cap)s%(name)s object.
 *
 * Return value: a newly created #Lasso%(prefix_cap)s%(name)s object
 **/
Lasso%(prefix_cap)s%(name)s*
lasso_%(category)s%(file_name)s_new()
{
\treturn g_object_new(LASSO_TYPE_%(category_upper)s%(file_name_upper)s, NULL);
}
""" % self.__dict__)

        if ('content', 'text-child') in self.elements:
            s.append("""
/**
 * lasso_%(category)s%(file_name)s_new_with_string:
 * @content:
 *
 * Creates a new #Lasso%(prefix_cap)s%(name)s object and initializes it
 * with @content.
 *
 * Return value: a newly created #Lasso%(prefix_cap)s%(name)s object
 **/
Lasso%(prefix_cap)s%(name)s*
lasso_%(category)s%(file_name)s_new_with_string(const char *content)
{
\tLasso%(prefix_cap)s%(name)s *object;
\tobject = g_object_new(LASSO_TYPE_%(category_upper)s%(file_name_upper)s, NULL);
\tobject->content = g_strdup(content);
\treturn object;
}
""" % self.__dict__)


        if ('text-child-int') in self.elements:
            s.append("""
/**
 * lasso_%(category)s%(file_name)s_new_with_int:
 * @content:
 *
 * Creates a new #Lasso%(prefix_cap)s%(name)s object and initializes it
 * with @content.
 *
 * Return value: a newly created #Lasso%(prefix_cap)s%(name)s object
 **/
Lasso%(prefix_cap)s%(name)s*
lasso_%(category)s%(file_name)s_new_with_int(int content)
{
\tLasso%(prefix_cap)s%(name)s *object;
\tobject = g_object_new(LASSO_TYPE_%(category_upper)s%(file_name_upper)s, NULL);
\tobject->content = content;
\treturn object;
}
""" % self.__dict__)

        if full_constructors.has_key(self.file_name):
            s.append(full_constructors.get(self.file_name)[1] + '\n')

        return '\n'.join(s)


    def generate_swig(self):
        s = []
        s.append("""/* $Id: %(file_name)s.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef SWIGPHP4
%%rename(%(prefix_cap)s%(name)s) Lasso%(prefix_cap)s%(name)s;
#endif
typedef struct {""" % self.__dict__)

        any_attribute = False
        for elem in self.elements + self.attributes:
            oname, type = elem[:2]
            if oname in ('signed', ): # reserved keywords
                oname = oname + '_'
            if type.startswith('xs:'):
                type = type[3:]
            if type == 'boolean':
                type = 'gboolean'
                name = oname
            elif type in ('unsignedShort', 'nonNegativeInteger', 'integer'):
                type = 'int'
                name = oname
            elif type in get_str_classes():
                type = 'char'
                name = '*'+oname
            elif type == 'any':
                any_attribute = True
                name = None # skip it here
            elif elem in self.attributes:
                # fallback for other attributes
                type = 'char'
                name = '*'+oname
            else:
                name = None
                if 'XXX' in ref_to_class_name(type):
                    continue
            if name:
                if oname[0] in string.uppercase:
                    lname = oname[0].lower() + oname[1:]
                    s.append("""#ifndef SWIGPHP4
\t%%rename(%s) %s;
#endif""" % (lname, oname))
                s.append('\t%s %s;' % (type, name))

        s.append('} Lasso%(prefix_cap)s%(name)s;' % self.__dict__)
        s.append('%%extend Lasso%(prefix_cap)s%(name)s {\n' % self.__dict__)

        swig_elems = []

        for elem in self.elements + self.attributes:
            name, type = elem[:2]
            if type.startswith('xs:'):
                type = type[3:]
            oname = name
            if type in ['GList', 'boolean', 'unsignedShort', 'nonNegativeInteger',
                    'integer'] + get_str_classes():
                continue
            else:
                type = ref_to_class_name(type)
                if 'XXX' in type:
                    continue

            name = '*'+name

            if oname[0] in string.uppercase:
                lname = oname[0].lower() + oname[1:]
                s.append("""#ifndef SWIGPHP4
\t%%rename(%s) %s;
#endif""" % (lname, oname))
            swig_elems.append((None, type, oname))
            if type.startswith('Lasso'):
                s.append('\t%%newobject %s_get;' % name)
            s.append('\t%s %s;\n' % (type, name))

        base_class_name = self.base_class_name
        while base_class_name:
            base_class = classes.get(base_class_name.replace('Saml2', '').replace('Samlp2', ''))
            if not base_class:
                break
            s.append('\t/* inherited from %s */' % base_class_name)

            for elem in base_class.elements + base_class.attributes:
                name, type = elem[:2]
                if type.startswith('xs:'):
                    type = type[3:]
                oname = name
                if type == 'boolean':
                    type = 'gboolean'
                elif type in ('unsignedShort', 'nonNegativeInteger', 'integer'):
                    type = 'int'
                elif type in get_str_classes():
                    type = 'char'
                    name = '*'+name
                elif type == 'GList':
                    name = None
                else:
                    type = ref_to_class_name(type)
                    name = '*'+name
                if not name:
                    continue
                if oname[0] in string.uppercase:
                    lname = oname[0].lower() + oname[1:]
                    s.append("""#ifndef SWIGPHP4
\t%%rename(%s) %s;
#endif""" % (lname, name))

                swig_elems.append((base_class, type, oname))
                if type.startswith('Lasso'):
                    s.append('\t%%newobject %s_get;' % name)
                s.append('\t%s %s;' % (type, name))
                if type.startswith('Lasso'):
                    s.append('')

            base_class_name = base_class.base_class_name

        if any_attribute:
            s.append("""\
\t/* any attribute */
\t%%immutable attributes;
\t%%newobject attributes_get;
\tLassoStringDict *attributes;
""" % self.__dict__)

        s.append("""\
\t/* Constructor, Destructor & Static Methods */
\tLasso%(prefix_cap)s%(name)s();
\t~Lasso%(prefix_cap)s%(name)s();

\t/* Method inherited from LassoNode */
\t%%newobject dump;
\tchar* dump();
}""" % self.__dict__)

        s.append("""
%{
""")
        if swig_elems:
            base_class = swig_elems[0][0]
            if base_class is not self:
                base_class = None

        for elem in swig_elems:
            bclass, type, name = elem[:3]
            if bclass != base_class:
                s.append('/* inherited from %s */\n' % bclass.name)
                base_class = bclass

            s.append('/* %s */' % name)

            if bclass is None:
                if type.startswith('Lasso'):
                    s.append("""
#define Lasso%(prefix_cap)s%(name)s_get_%(elem_name)s(self) get_node((self)->%(elem_name)s)
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_get(self) get_node((self)->%(elem_name)s)
#define Lasso%(prefix_cap)s%(name)s_set_%(elem_name)s(self,value) set_node((gpointer*)&(self)->%(elem_name)s, (value))
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_set(self,value) set_node((gpointer*)&(self)->%(elem_name)s, (value))
                    """ % {
                    'prefix_cap': self.prefix_cap,
                    'name': self.name,
                    'elem_name': name,
                    })
                else:
                    s.append("""
#define Lasso%(prefix_cap)s%(name)s_get_%(elem_name)s(self) self->%(elem_name)s
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_get(self) self->%(elem_name)s""" % {
                    'prefix_cap': self.prefix_cap,
                    'name': self.name,
                    'elem_name': name,
                    })
                    if type in ('boolean', 'unsignedShort'):
                        s.append("""
#define Lasso%(prefix_cap)s%(name)s_set_%(elem_name)s(self,value) (self)->%(elem_name)s = (value)
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_set(self,value) (self)->%(elem_name)s = (value)""" % {
                        'prefix_cap': self.prefix_cap,
                        'name': self.name,
                        'elem_name': name,
                        })
                    else: # string
                        s.append("""
#define Lasso%(prefix_cap)s%(name)s_set_%(elem_name)s(self,value) set_string(&(self)->%(elem_name)s, (value))
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_set(self,value) set_string(&(self)->%(elem_name)s, (value))""" % {
                        'prefix_cap': self.prefix_cap,
                        'name': self.name,
                        'elem_name': name,
                        })
            else:
                parent_upper = bclass.file_name_upper
                if self.prefix.startswith('ws'):
                    parent_upper = 'WS_' + bclass.file_name_upper
                else:
                    parent_upper = 'IDWSF2_' + bclass.file_name_upper
                if type.startswith('Lasso'):
                    s.append("""
#define Lasso%(prefix_cap)s%(name)s_get_%(elem_name)s(self) get_node(LASSO_%(parent_upper)s(self)->%(elem_name)s)
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_get(self) get_node(LASSO_%(parent_upper)s(self)->%(elem_name)s)
#define Lasso%(prefix_cap)s%(name)s_set_%(elem_name)s(self,value) set_node((gpointer*)&LASSO_%(parent_upper)s(self)->%(elem_name)s, (value))
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_set(self,value) set_node((gpointer*)&LASSO_%(parent_upper)s(self)->%(elem_name)s, (value))
                    """ % {
                    'prefix_cap': self.prefix_cap,
                    'name': self.name,
                    'elem_name': name,
                    'parent_upper': parent_upper
                    })
                else:
                    s.append("""
#define Lasso%(prefix_cap)s%(name)s_get_%(elem_name)s(self) LASSO_%(parent_upper)s(self)->%(elem_name)s
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_get(self) LASSO_%(parent_upper)s(self)->%(elem_name)s""" % {
                    'prefix_cap': self.prefix_cap,
                    'name': self.name,
                    'elem_name': name,
                    'parent_upper': parent_upper
                    })
                    if type in ('boolean', 'unsignedShort', 'nonNegativeInteger', 'integer'):
                        s.append("""
#define Lasso%(prefix_cap)s%(name)s_set_%(elem_name)s(self,value) LASSO_%(parent_upper)s(self)->%(elem_name)s = (value)
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_set(self,value) LASSO_%(parent_upper)s(self)->%(elem_name)s = (value)""" % {
                        'prefix_cap': self.prefix_cap,
                        'name': self.name,
                        'elem_name': name,
                        'parent_upper': parent_upper
                        })
                    else: # string
                        s.append("""
#define Lasso%(prefix_cap)s%(name)s_set_%(elem_name)s(self,value) set_string(&LASSO_%(parent_upper)s(self)->%(elem_name)s, (value))
#define Lasso%(prefix_cap)s%(name)s_%(elem_name)s_set(self,value) set_string(&LASSO_%(parent_upper)s(self)->%(elem_name)s, (value))""" % {
                        'prefix_cap': self.prefix_cap,
                        'name': self.name,
                        'elem_name': name,
                        'parent_upper': parent_upper
                        })
            s.append('')

        if any_attribute:
            s.append("""\
/* any attribute */
LassoStringDict* Lasso%(prefix_cap)s%(name)s_attributes_get(Lasso%(prefix_cap)s%(name)s *self);
#define Lasso%(prefix_cap)s%(name)s_get_attributes Lasso%(prefix_cap)s%(name)s_attributes_get
LassoStringDict* Lasso%(prefix_cap)s%(name)s_attributes_get(Lasso%(prefix_cap)s%(name)s *self) {
        return self->attributes;
}
/* TODO: implement attributes_set */
""" % self.__dict__)


        s.append("""
/* Constructors, destructors & static methods implementations */

#define new_Lasso%(prefix_cap)s%(name)s lasso_%(category)s%(file_name)s_new
#define delete_Lasso%(prefix_cap)s%(name)s(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define Lasso%(prefix_cap)s%(name)s_dump(self) lasso_node_dump(LASSO_NODE(self))

%%}

""" % self.__dict__)


        return '\n'.join(s)



def ref_to_class_name(s):
    if s == 'LassoNode':
        return s

    if ':' in s:
        ns = s.split(':')[0]
    else:
        ns = None

    if ns in ('saml', 'samlp'):
        return 'Lasso' + s.replace(':', '').replace('saml', 'Saml2').replace('Saml2p', 'Samlp2')

    if ns == 'util':
        return 'Lasso' + s.replace(':', '').replace('util', 'IdWsf2Util')

    if ns == 'tns':
        return 'Lasso' + s.replace(':', '').replace('tns', 'WsAddr')

    if ns == 'disco':
        return 'Lasso' + s.replace(':', '').replace('disco', 'IdWsf2Disco')

    if ns == 'dstref':
        return 'Lasso' + s.replace(':', '').replace('dstref', 'IdWsf2DstRef')

    return '/* XXX */ void'


classes = {}
string_classes = []

doms = {}

def get_prefixes_by_filename(filename):
    if filename == 'liberty-idwsf-disco-svc-v2.0.xsd':
        prefix = 'disco'
        prefix_cap = 'IdWsf2Disco'
    elif filename == 'liberty-idwsf-utility-v2.0.xsd':
        prefix = 'util'
        prefix_cap = 'IdWsf2Util'
    elif filename == 'liberty-idwsf-dst-v2.1.xsd':
        prefix = 'dst'
        prefix_cap = 'IdWsf2Dst'
    elif filename == 'liberty-idwsf-dst-ref-v2.1.xsd':
        prefix = 'dstref'
        prefix_cap = 'IdWsf2DstRef'
    elif filename == 'liberty-idwsf-security-mechanisms-v2.0.xsd':
        prefix = 'sec'
        prefix_cap = 'IdWsf2Sec'
    elif filename == 'liberty-idwsf-idmapping-svc-v2.0.xsd':
        prefix = 'ims'
        prefix_cap = 'IdWsf2Ims'
    elif filename == 'liberty-idwsf-subs-v1.0.xsd':
        prefix = 'subs'
        prefix_cap = 'IdWsf2Subs'
    elif filename == 'liberty-idwsf-subs-ref-v1.0.xsd':
        prefix = 'subsref'
        prefix_cap = 'IdWsf2SubsRef'
    elif filename == 'liberty-idwsf-people-service-v1.0.xsd':
        prefix = 'ps'
        prefix_cap = 'IdWsf2Ps'
    elif filename == 'liberty-idwsf-interaction-svc-v2.0.xsd':
        prefix = 'is'
        prefix_cap = 'IdWsf2Is'
    elif filename == 'liberty-idwsf-soap-binding.xsd':
        prefix = 'sbf'
        prefix_cap = 'IdWsf2Sbf'
    elif filename == 'liberty-idwsf-soap-binding-v2.0.xsd':
        prefix = 'sb2'
        prefix_cap = 'IdWsf2Sb2'
    elif filename == 'ws-addr.xsd':
        prefix = 'wsa'
        prefix_cap = 'WsAddr'
    elif filename == 'oasis-200401-wss-wssecurity-secext-1.0.xsd':
        prefix = 'wsse'
        prefix_cap = 'WsSec1'
    elif filename == 'oasis-200401-wss-wssecurity-utility-1.0.xsd':
        prefix = 'wsu'
        prefix_cap = 'WsUtil1'
    else:
        raise 'missing def for %s' % filename
    return prefix, prefix_cap

xsd_filenames = ['liberty-idwsf-utility-v2.0.xsd',
              'liberty-idwsf-disco-svc-v2.0.xsd',
              'liberty-idwsf-dst-v2.1.xsd',
              'liberty-idwsf-dst-ref-v2.1.xsd',
              'liberty-idwsf-security-mechanisms-v2.0.xsd',
              'liberty-idwsf-idmapping-svc-v2.0.xsd',
              'liberty-idwsf-subs-ref-v1.0.xsd',
              'liberty-idwsf-subs-v1.0.xsd',
              'liberty-idwsf-people-service-v1.0.xsd',
              'liberty-idwsf-interaction-svc-v2.0.xsd',
              'liberty-idwsf-soap-binding.xsd',
              'liberty-idwsf-soap-binding-v2.0.xsd',
              'ws-addr.xsd',
              'oasis-200401-wss-wssecurity-utility-1.0.xsd',
              'oasis-200401-wss-wssecurity-secext-1.0.xsd',
              ]

for filename in xsd_filenames:
    if filename.startswith('oasis-'):
        dom = xml.dom.minidom.parseString(file(filename).read().replace(
                    'xsd:', 'xs:').replace('xmlns:xsd=', 'xmlns:xs='))
    else:
        dom = xml.dom.minidom.parse(filename)
    prefix, prefix_cap = get_prefixes_by_filename(filename)
    doms[prefix] = dom
    classes[prefix] = {}

for filename in xsd_filenames:
    xsd_content = file(filename).read()
    if filename.startswith('oasis-'):
        xsd_content = xsd_content.replace('xsd:', 'xs:').replace('xmlns:xsd=', 'xmlns:xs=')
    prefix, prefix_cap = get_prefixes_by_filename(filename)
    dom = doms[prefix]

    for element in dom.getElementsByTagName('xs:complexType') + dom.getElementsByTagName('xs:element'):

        string_wrapper = False

        if not element.attributes.has_key('name'):
            continue

        if element.nodeName == 'xs:element':
            if element.getElementsByTagName('xs:complexType'):
                pass
            else:
                if not element.attributes.get('type'):
                    continue
                if not element.attributes.get('type').value == 'samlp:StatusResponseType':
                    if element.attributes.get('name').value not in (
                            'Abstract', 'ProviderID', 'ServiceType'):
                        continue
                    string_wrapper = True

        if element.nodeName == 'xs:complexType' and element.getElementsByTagName('xs:simpleContent'):
            force_class_generation = False
            if filename == 'liberty-idwsf-dst-ref-v2.1.xsd':
                n = element.attributes['name'].value[:-4] # strip "Type"
                if n in ('Select', 'TestOp', 'Sort'):
                    string_classes.append('dstref:%s' % n)
                    continue
                force_class_generation = True
            elif not filename.startswith('ws'):
                continue

        if element.nodeName == 'xs:element':
            class_name = element.attributes['name'].value
        else:
            full_type_name = element.attributes['name'].value
            class_name = full_type_name
            if class_name.endswith('Type'):
                class_name = class_name[:-4]
        file_name = prefix + '_' + re.sub(r'[a-z]([A-Z])', rep, class_name).lower()
        file_name = file_name.replace( '_name_id', '_name_id_').replace(
                '_idp', '_idp_').replace('_md', '_md_')
        if file_name.endswith('_'):
            file_name = file_name[:-1]

        klass = LassoClass()
        klass.prefix = prefix
        if klass.prefix.startswith('ws'):
            klass.category = ''
            klass.category_upper = ''
        else:
            klass.category = 'idwsf2_'
            klass.category_upper = 'IDWSF2_'
        klass.prefix_cap = prefix_cap
        klass.schema_filename = filename
        klass.name = class_name
        klass.file_name = file_name
        klass.file_name_upper = file_name.upper()
        klass.elements = []
        klass.attributes = []

        t = [x for x in dom.getElementsByTagName('xs:element') + dom.getElementsByTagName('xsd:element') if x.attributes.has_key('type') and x.attributes['type'].value.split(':')[-1] == '%sType' % klass.name]
        if len(t) == 1 and t[0].attributes['name'].value.lower() != klass.name.lower():
            # if there is only one reference to this type and this reference uses another name,
            # also use that other name
            klass.node_set_name = t[0].attributes['name'].value

        if klass.prefix == 'dstref' and klass.name in \
                ('Query', 'QueryResponse', 'Modify', 'ModifyResponse'):
            klass.has_custom_ns = True

        if element.nodeName == 'element':
            schema_fragment = '<xs:element name="%s" type="samlp:StatusResponseType"/>' % class_name
        elif element.nodeName == 'xs:element':
            lookup_fragment_re = re.compile(
                    '(<xs:element name="%s")(.*?)(</xs:element>)' % klass.name, re.DOTALL)
            try:
                schema_fragment = ''.join(lookup_fragment_re.findall(xsd_content)[0])
            except IndexError:
                schema_fragment = ''
            if string_wrapper:
                lookup_fragment_re = re.compile(
                        '(<xs:element name="%s")(.*?)(/>)' % klass.name, re.DOTALL)
                schema_fragment = ''.join(lookup_fragment_re.findall(xsd_content)[0])
        else:
            lookup_fragment_re = re.compile('(<xs:complexType name="%s")(.*?)(</xs:complexType>)' % full_type_name, re.DOTALL)
            try:
                schema_fragment = ''.join(lookup_fragment_re.findall(xsd_content)[0])
            except IndexError:
                if klass.file_name == 'wsu_timestamp':
                    raise 'xXX'
                schema_fragment = ''
            if '<xs:complexType name="%s"/>' % full_type_name in schema_fragment:
                # special casing ultra simple complexType (samlp:Terminate)
                schema_fragment = '<xs:complexType name="%s"/>' % full_type_name
        indent = 0
        schema_lines = []
        for s in [x.strip() for x in schema_fragment.splitlines()]:
            if s.startswith('</'):
                indent -= 1
            s = s.replace('\t', ' ')
            if len(s) < 90:
                schema_lines.append('  '*indent + s)
            else:
                for idx in range(70, 50, -5):
                    try:
                        s_i = s[idx:].index(' ')
                    except ValueError:
                        continue
                    schema_lines.append('  '*indent + s[:idx+s_i])
                    if len(s[idx+1+s_i:]) < 90:
                        schema_lines.append('  '*indent + ' '*8 + s[idx+1+s_i:])
                    else:
                        s2 = s[idx+1+s_i:]
                        idx = 50
                        s_i2 = s2[idx:].index(' ')
                        schema_lines.append('  '*indent + ' '*8 + s2[:idx+s_i2])
                        schema_lines.append('  '*indent + ' '*8 + s2[s_i2+idx+1:])
                    break
            if not s:
                continue
            if s[0] == '<' and not s.startswith('</') and not s.endswith('/>'):
                indent += 1
        klass.schema_fragment = '\n'.join([' * ' + x for x in schema_lines])

        for attr in element.getElementsByTagName('xs:attribute'):
            if attr.attributes.has_key('ref'):
                ref = attr.attributes['ref'].value
                if ':' in ref:
                    ns, name = ref.split(':')
                else:
                    name = ref
                    ns = prefix
                if ns == 'lu':
                    ns = 'util'
                elif ns not in doms.keys():
                    print 'ref:', ref
                    raise 'NS: %s' % ns
                typ = [x for x in doms[ns].getElementsByTagName('xs:attribute') \
                        if x.attributes.get('name') and x.attributes['name'].value == name][0]
                name = typ.attributes['name'].value
                elem_type = '%s:%s' % (ns, typ.attributes['type'].value)
            else:
                name = attr.attributes['name'].value
                if attr.attributes.has_key('type'):
                    type = attr.attributes['type'].value
                elif attr.getElementsByTagName('xs:simpleType') and \
                        attr.getElementsByTagName('xs:restriction'):
                    restrict = attr.getElementsByTagName('xs:restriction')[0]
                    type = restrict.attributes['base'].value
                    # TODO: if present, list xs:enumeration value in comment
            if attr.attributes.has_key('use') and attr.attributes['use'].value == 'optional':
                optional = True
            else:
                optional = False
            klass.attributes.append((name, type, optional))

        for attr_group in element.getElementsByTagName('xs:attributeGroup'):
            ref = attr_group.attributes['ref'].value.replace('saml:', '')
            if ':' in ref:
                ns, ref = ref.split(':', 2)
                if ns == klass.prefix:
                    ns = None
            else:
                ns = None
            if ns is None:
                group_dom = dom
            else:
                group_dom = doms[ns]

            attr_gr = [x for x in group_dom.getElementsByTagName('xs:attributeGroup') \
                    if x.attributes.get('name') and x.attributes.get('name').value == ref][0]
            for attr in attr_gr.getElementsByTagName('xs:attribute'):
                if attr.attributes.has_key('ref'):
                    ref = attr.attributes['ref'].value
                    if ':' in ref:
                        ns, name = ref.split(':')
                    else:
                        name = ref
                        ns = prefix
                    if ns == 'lu':
                        ns = 'util'
                    elif ns not in doms.keys():
                        print 'ref:', ref
                        raise 'NS: %s' % ns
                    typ = [x for x in doms[ns].getElementsByTagName('xs:attribute') \
                            if x.attributes.get('name') and x.attributes['name'].value == name][0]
                    name = typ.attributes['name'].value
                    if typ.attributes.has_key('type'):
                        if ':' in typ.attributes['type'].value:
                            elem_type = typ.attributes['type'].value
                        else:
                            elem_type = '%s:%s' % (ns, typ.attributes['type'].value)

                    else:
                        elem_type = 'xs:string'

                    if attr.attributes.has_key('name'):
                        klass.attributes.append((attr.attributes['name'].value, elem_type))
                    else:
                        klass.attributes.append((name, elem_type))
                else:
                    if attr.attributes.has_key('type'):
                        if attr.attributes.has_key('use') and \
                                attr.attributes['use'].value == 'optional':
                            optional = True
                        else:
                            optional = False
                        klass.attributes.append(
                            (attr.attributes['name'].value, attr.attributes['type'].value, optional))
                    else:
                        # should actually look down, probably a simple type
                        if attr.attributes['name'].value in ['setReq', 'notSorted']:
                            klass.attributes.append(
                                (attr.attributes['name'].value, 'string'))
                        else:
                            raise str('No type for attr %s in attributeGroup' % attr.attributes['name'].value)
            if attr_gr.getElementsByTagName('xs:anyAttribute'):
                klass.attributes.append(('attributes', 'any'))


        if element.getElementsByTagName('xs:anyAttribute'):
            klass.attributes.append(('attributes', 'any'))

        extension = element.getElementsByTagName('extension') + \
                element.getElementsByTagName('xs:extension')
        if string_wrapper:
            klass.base_prefix = None
            klass.base_class_name = 'Node'
            klass.elements.append( ('content', 'text-child') )
        elif extension:
            base = extension[0].attributes['base'].value
            klass.base_prefix = None
            if base in get_str_classes() + ['xs:unsignedLong']:
                if not extension[0].getElementsByTagName('attribute') and ( \
                        not extension[0].getElementsByTagName('xs:attribute') and ( \
                        not extension[0].getElementsByTagName('xs:anyAttribute'))) and (
                        not force_class_generation):
                    string_classes.append(klass.name)
                else:
                    klass.base_class_name = 'Node'
                    if base in ['xs:unsignedLong']:
                        klass.elements.append( ('content', 'text-child-int') )
                    else:
                        klass.elements.append( ('content', 'text-child') )
            else:
                if ':' in base:
                    ns, name = base[:-4].split(':')
                    if ns == 'xs':
                        raise 'base class is %r:!' % base
                    if ns != prefix:
                        klass.base_class_name = name
                        klass.base_prefix = ns
                    else:
                        base_ext = get_by_name_and_attribute(dom, 'xs:complexType',
                                'name', name + 'Type')
                        if base_ext and base_ext[0].getElementsByTagName('xs:simpleContent'):
                            klass.base_class_name = 'Node'
                            if base in ('dstref:AppDataType',):
                                # AppDataType in schema is just an example; schemas
                                # derived from dstref will have random xml nodes here
                                klass.base_class_name = name
                                #klass.elements.append( ('any', 'GList', 'xmlNode'))
                            else:
                                klass.elements.append( ('content', 'text-child') )
                        else:
                            klass.base_class_name = name
                else:
                    klass.base_class_name = base[:-4]

        else:
            klass.base_class_name = 'Node'
            if element.nodeName == 'element':
                klass.base_class_name = 'StatusResponse'

        if klass.name == 'AppData':
            # AppData is just a template in Data Service, replace the base
            # definition (xs:string) to allow everything...
            klass.elements = [['any', 'GList', 'xmlNode']]

        classes[prefix][klass.name] = klass

        for elem in element.getElementsByTagName('xs:element'):
            if elem.attributes.has_key('ref'):
                ref = elem.attributes['ref'].value
                if not ':' in ref:
                    refered = get_by_name_and_attribute(dom, 'xs:element', 'name', ref)
                    if refered:
                        if len(refered) >= 1:
                            print >> sys.stderr, 'W: more than one refered'
                        refered = refered[0]
                        if refered.attributes.has_key('type'):
                            elem_type = refered.attributes['type'].value
                            name = refered.attributes['name'].value
                            if not ':' in elem_type:
                                if klass.prefix == 'util':
                                    elem_type = 'util:%s' % elem_type
                        else:
                            elem_type = 'xs:string' # XXX
                            name = refered.attributes['name'].value
                else:
                    ns, name = ref.split(':')
                    if ns == 'lu':
                        ns = 'util'
                    if ns == 'tns':
                        ns = 'wsa'
                    #if name in [x[0] for x in klass.elements]:
                    #    continue

                    if ns == 'ds':
                        if name == 'Signature':
                            klass.has_ds_signature = True
                            elem_type = 'ds:Signature'
                        else:
                            print >> sys.stderr, 'W: missing xmldsig support for %s' % ref
                    elif not doms.has_key(ns):
                        print >> sys.stderr, 'W: missing dom for', ns
                        elem_type = 'XXX'
                        if ns == 'samlp':
                            elem_type = ref
                    else:
                        typ = [x for x in doms[ns].getElementsByTagName('xs:element') \
                                if x.attributes.get('name') and x.attributes['name'].value == name][0]
                        if typ.getElementsByTagName('xs:simpleType'):
                            elem_type = 'xs:string'
                        elif ':' in typ.attributes['type'].value:
                            elem_type = typ.attributes['type'].value
                        else:
                            elem_type = '%s:%s' % (ns, typ.attributes['type'].value)
            else:
                typ = elem
                if typ.attributes.has_key('type'):
                    elem_type = elem.attributes['type'].value
                    name = elem.attributes['name'].value
                elif typ.getElementsByTagName('xs:complexType'):
                    name = elem.attributes['name'].value
                    if name == 'Item':
                        # special case: interaction svc, SelectType/Item
                        klass.elements = [('Item', 'GList', 'SelectItem')]
                        klass.attributes = []
                        break
                    else:
                        raise 'XXX'
                else:
                    raise 'XXX'

            if elem_type.endswith('Type'):
                elem_type = elem_type[:-4]

            if elem_type == 'ds:Signature':
                pass
            else:
                klass.elements.append( [name, elem_type] )
                if elem.attributes.has_key('maxOccurs') and \
                        elem.attributes.get('maxOccurs').value == 'unbounded':
                    klass.elements[-1].insert(1, 'GList')
                    if not ':' in klass.elements[-1][2]:
                        klass.elements[-1][2] = '%s:%s' % (klass.prefix, klass.elements[-1][2])

            #elif ns == 'ds' and name == 'Signature':
            #    klass.has_ds_signature = True
            #else:
            #    elem_type = ref
            #    klass.elements.append( (name, elem_type) )
        for elem in element.getElementsByTagName('any') + element.getElementsByTagName('xs:any'):
            if klass.name in ('ArtifactResponse', # saml
                    'RequestedService', # disco
                    'TokenPolicy', 'Token', # sec
                    #'Framework', # sbf
                    #'TargetIdentity', 'UsageDirective', # sb2
                    #'Timestamp', # wsu
                    #'UsernameToken', 'Embedded', 'SecurityTokenReference', 'SecurityHeader',
                    #'TransformationParameters', # wsse
                    #'extension', # util
                    ):
                klass.elements.append( ('any', 'LassoNode'))
            elif klass.name in (
                    'EndpointReference', 'ReferenceParameters', 'Metadata', 'AttributedAny', # wsa
                    'SecurityHeader', # wsse
                    ):
                klass.elements.append( ('any', 'GList', 'LassoNode'))
            else:
                print >> sys.stderr, 'W: any occurence for %s (prefix: %s)' % (klass.name, prefix)
            # XXX... other occurences of <any>

        print klass.name
        for elem in klass.elements:
            print '  ', elem
        print '-'*40

def get_ordered_classes():
    all_classes = []
    for k in classes.keys():
        all_classes.extend(classes[k].values())
    clsses = []
    while all_classes:
        for c in all_classes:
            if c.base_class_name == 'Node' or c.base_class_name in [
                        '%s%s' % (x.prefix_cap, x.name) for x in clsses]:
                all_classes.remove(c)
                clsses.append(c)
                break
    return clsses


def generate_swig_inheritance(prefix):
    s = []
    clsses = get_ordered_classes()

    for klass in clsses:
        if prefix == 'ws' and not klass.prefix.startswith('ws'):
            continue
        if prefix != 'ws' and klass.prefix.startswith('ws'):
            continue
        s.append('SET_NODE_INFO(%s%s, %s)' % (
                klass.prefix_cap, klass.name, klass.base_class_name))
    s.append('')
    return '\n'.join(s) + '\n'

def generate_swig_main(prefix):
    s = []
    s.append('%{')

    clsses = get_ordered_classes()

    for klass in clsses:
        if prefix == 'ws' and not klass.prefix.startswith('ws'):
            continue
        if prefix != 'ws' and klass.prefix.startswith('ws'):
            continue
        if prefix == 'ws':
            s.append('#include <lasso/xml/ws/%(file_name)s.h>' % klass.__dict__)
        else:
            s.append('#include <lasso/xml/id-wsf-2.0/%(file_name)s.h>' % klass.__dict__)
    s.append('%}')

    for klass in clsses:
        if prefix == 'ws' and not klass.prefix.startswith('ws'):
            continue
        if prefix != 'ws' and klass.prefix.startswith('ws'):
            continue
        s.append('%%include %(file_name)s.i' % klass.__dict__)

    return '\n'.join(s)


#import pprint
#pprint.pprint(classes)

for klass_p in classes.keys():
    for klass in classes[klass_p].values():
        #print klass_p, klass.name
        if klass.base_class_name != 'Node':
            #print '  <-', klass.base_prefix, ':', klass.base_class_name
            if klass.base_prefix:
                prefix = klass.base_prefix
            else:
                prefix = klass.prefix
            if prefix == 'lu':
                prefix = 'util'
            k = classes[prefix][klass.base_class_name]
            klass.base_class_type = 'LASSO_TYPE_' + k.category_upper + k.file_name_upper
            klass.base_class_name = '%s%s' % (
                    classes[prefix][klass.base_class_name].prefix_cap, klass.base_class_name)
        else:
            klass.base_class_type = 'LASSO_TYPE_NODE'
        if klass.prefix.startswith('ws'):
            file('ws/%s.h' % klass.file_name, 'w').write(klass.generate_header())
            file('ws/%s.c' % klass.file_name, 'w').write(klass.generate_source())
            file('swig-ws/%s.i' % klass.file_name, 'w').write(klass.generate_swig())
        else:
            file('id-wsf-2.0/%s.h' % klass.file_name, 'w').write(klass.generate_header())
            file('id-wsf-2.0/%s.c' % klass.file_name, 'w').write(klass.generate_source())
            file('swig-id-wsf-2.0/%s.i' % klass.file_name, 'w').write(klass.generate_swig())

file('swig-ws/inheritance.h', 'w').write(generate_swig_inheritance('ws'))
file('swig-ws/main.h', 'w').write(generate_swig_main('ws'))

file('swig-id-wsf-2.0/inheritance.h', 'w').write(generate_swig_inheritance('id-wsf-2.0'))
file('swig-id-wsf-2.0/main.h', 'w').write(generate_swig_main('id-wsf-2.0'))

def generate_makefile_am(dir):
    makefile_am = file('%s/Makefile.am' % dir, 'w')
    if dir == 'id-wsf-2.0':
        lib_suffix = 'id-wsf-2'
    else:
        lib_suffix = dir
    makefile_am.write('''\
liblassoincludedir = $(includedir)/lasso/xml/%s

INCLUDES = \\
\t-I$(top_srcdir) \\
\t-I$(top_srcdir)/lasso \\
\t$(LASSO_CORE_CFLAGS) \\
\t-DG_LOG_DOMAIN=\\"lasso\\"

noinst_LTLIBRARIES = liblasso-xml-%s.la

liblasso_xml_%s_la_SOURCES = \\
%s

liblassoinclude_HEADERS = \\
%s

''' % ( dir,
            lib_suffix,
            lib_suffix.replace('-', '_'),
            '\n'.join(['\t%s \\' % x for x in sorted(os.listdir(dir)) if x.endswith('.c')])[:-2],
            '\n'.join(['\t%s \\' % x for x in sorted(os.listdir(dir)) if x.endswith('.h')])[:-2]))


def generate_swig_makefile_am(dir):
    makefile_am = file('%s/Makefile.am' % dir, 'w')
    makefile_am.write('''\
EXTRA_DIST = \\
\tinheritance.h \\
\tmain.h \\
\tMakefile.am \\
%s
''' % '\n'.join(['\t%s \\' % x for x in sorted(os.listdir(dir)) if x.endswith('.i')])[:-2])



generate_makefile_am('id-wsf-2.0')
generate_makefile_am('ws')

generate_swig_makefile_am('swig-id-wsf-2.0')
generate_swig_makefile_am('swig-ws')
