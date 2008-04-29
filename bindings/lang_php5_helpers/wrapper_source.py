# Lasso - A free implementation of the Liberty Alliance specifications.
# 
# Copyright (C) 2004-2007 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file in top-level directory.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import sys

import utils

class WrapperSource:
    def __init__(self, binding_data, fd):
        self.binding_data = binding_data
        self.fd = fd
        self.functions_list = []

    def is_object(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*', 'GList*',
                'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

    def generate(self):
        self.generate_header()
        self.generate_constants()
        self.generate_middle()
        for m in self.binding_data.functions:
            self.generate_function(m)
        for c in self.binding_data.structs:
            self.generate_members(c)
            for m in c.methods:
                self.generate_function(m)
        self.generate_functions_list()
        self.generate_footer()

    def generate_header(self):
        self.functions_list.append('lasso_get_object_typename')

        print >> self.fd, '''\
/* this file has been generated automatically; do not edit */

#include <php.h>
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <lasso/lasso.h>
'''
        for h in self.binding_data.headers:
            print >> self.fd, '#include <%s>' % h
        print >> self.fd, ''

        print >> self.fd, '''\
#include "php_lasso.h"

int le_lasso_server;

ZEND_GET_MODULE(lasso)

typedef struct {
    GObject *obj;
    char *typename;
} PhpGObjectPtr;

PHP_FUNCTION(lasso_get_object_typename)
{
    PhpGObjectPtr *self;
    zval *zval_self;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zval_self) == FAILURE) {
        RETURN_FALSE;
    }

    ZEND_FETCH_RESOURCE(self, PhpGObjectPtr *, &zval_self, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
    RETURN_STRING(self->typename, 1);
}

PHP_MINIT_FUNCTION(lasso)
{
    le_lasso_server = zend_register_list_destructors_ex(NULL, NULL, PHP_LASSO_SERVER_RES_NAME, module_number);
'''

    def generate_constants(self):
        constant_types = {
            'i': 'LONG',
            's': 'STRING'
        }
        print >> self.fd, '    /* Constants (both enums and defines) */'
        for c in self.binding_data.constants:
            print >> self.fd, '    REGISTER_%(type)s_CONSTANT("%(name)s", %(name)s, CONST_CS|CONST_PERSISTENT);' \
                % {'type': constant_types[c[0]], 'name': c[1]}
        print >> self.fd, ''

    def generate_middle(self):
        print >> self.fd, '''\
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(lasso)
{
    return SUCCESS;
}
'''

    def return_value(self, vtype, options):
        if vtype is None:
            print >> self.fd, '    RETURN_NULL();'
        elif vtype == 'gboolean':
            print >> self.fd, '    RETURN_BOOL(return_c_value);'
        elif vtype in ['int', 'gint'] + self.binding_data.enums:
            print >> self.fd, '    RETURN_LONG(return_c_value);'
        elif vtype in ('char*', 'gchar*'):
            print >> self.fd, '''\
    if (return_c_value) {
        RETURN_STRING(return_c_value, 1);
    } else {
        RETURN_NULL();
    }'''
        elif vtype in ('const char*', 'const gchar*'):
            print >> self.fd, '''\
    if (return_c_value) {
        RETURN_STRING(estrndup(return_c_value, strlen(return_c_value)), 0);
    } else {
        RETURN_NULL();
    }'''
        elif vtype in ('GList*',) and options.get('elem_type') == 'char*':
            print >> self.fd, '''\
    array_init(return_value);
    for (item = g_list_first(return_c_value); item != NULL; item = g_list_next(item)) {
        add_next_index_string(return_value, item->data, 1);
    }
    
'''
        elif vtype in ('GList*',) and options.get('elem_type') != 'char*':
            print >> self.fd, '    RETURN_NULL();'
        else:
            print >> self.fd, '''\
    if (return_c_value) {
        self = (PhpGObjectPtr *)emalloc(sizeof(PhpGObjectPtr));
        self->obj = G_OBJECT(return_c_value);
        self->typename = estrdup(G_OBJECT_TYPE_NAME(G_OBJECT(return_c_value)));
        ZEND_REGISTER_RESOURCE(return_value, self, le_lasso_server);
    } else {
        RETURN_NULL();
    }'''

    def generate_function(self, m):
        name = m.name
        self.functions_list.append(name)
        print >> self.fd, '''PHP_FUNCTION(%s)
{''' % name
        parse_tuple_format = ''
        parse_tuple_args = []
        for arg in m.args:
            arg_type, arg_name, arg_options = arg
            if arg_type in ('char*', 'const char*', 'gchar*', 'const gchar*'):
                arg_type = arg_type.replace('const ', '')
                #if arg_options.get('optional'):
                #    if not '|' in parse_tuple_format:
                #        parse_tuple_format.append('|')
                #    parse_tuple_format.append('z')
                #else:
                #    parse_tuple_format.append('s')
                parse_tuple_format += 's'
                parse_tuple_args.append('&%s_str, &%s_len' % (arg_name, arg_name))
                print >> self.fd, '    %s %s = NULL;' % ('char*', arg_name)
                print >> self.fd, '    %s %s_str = NULL;' % ('char*', arg_name)
                print >> self.fd, '    %s %s_len = 0;' % ('int', arg_name)
            elif arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums:
                parse_tuple_format += 'l'
                parse_tuple_args.append('&%s' % arg_name)
                print >> self.fd, '    %s %s;' % ('long', arg_name)
            elif arg_type == 'GList*':
                print >> sys.stderr, 'E: GList argument in', name
                print >> self.fd, '    %s %s = NULL;' % (arg_type, arg_name)
            else:
                parse_tuple_format += 'r'
                parse_tuple_args.append('&zval_%s' % arg_name)
                print >> self.fd, '    %s %s = NULL;' % (arg_type, arg_name)
                print >> self.fd, '    %s zval_%s = NULL;' % ('zval*', arg_name)
                print >> self.fd, '    %s cvt_%s = NULL;' % ('PhpGObjectPtr*', arg_name)

        if m.return_type:
            print >> self.fd, '    %s return_c_value;' % m.return_type
        if self.is_object(m.return_type):
            print >> self.fd, '    PhpGObjectPtr *self;'
        print >> self.fd, ''

        parse_tuple_args = ', '.join(parse_tuple_args)
        if parse_tuple_args:
            parse_tuple_args = ', ' + parse_tuple_args

        print >> self.fd, '''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "%s"%s) == FAILURE) {
        RETURN_FALSE;
    }
''' % (parse_tuple_format, parse_tuple_args)

        for f, arg in zip(parse_tuple_format, m.args):
            if f == 's':
                print >> self.fd, '''\
    if (%(name)s_str && strcmp(%(name)s_str, "") != 0) {
        %(name)s = estrndup(%(name)s_str, %(name)s_len);
    } ''' % {'name': arg[1]}
            elif f == 'r':
                print >> self.fd, '    ZEND_FETCH_RESOURCE(cvt_%s, PhpGObjectPtr *, &zval_%s, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);' % (arg[1], arg[1])
                print >> self.fd, '    %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1])

        if m.return_type is not None:
            print >> self.fd, '    return_c_value =',
        else:
            print >> self.fd, '   ',
        print >> self.fd, '%s(%s);' % (m.name, ', '.join([x[1] for x in m.args]))

        self.return_value(m.return_type, {})

        print >> self.fd, '}'
        print >> self.fd, ''


    def generate_getter(self, klassname, m_type, m_name, m_options):
        if m_type == 'GList*' and m_options.get('elem_type') != 'char*':
            print >> sys.stderr, 'E: GList argument : %s of %s, with type : %s' % (m_name, klassname, m_options.get('elem_type'))
            return

        function_name = '%s_%s_get' % (klassname, format_attribute(m_name))
        function_name = '%s_%s_get' % (klassname, utils.format_as_camelcase(m_name))
        print >> self.fd, '''PHP_FUNCTION(%s)
{''' % function_name
        self.functions_list.append(function_name)


        if self.is_object(m_type):
            print >> self.fd, '    %s return_c_value = NULL;' % m_type
        else:
            print >> self.fd, '    %s return_c_value;' % m_type
        print >> self.fd, '    %s* this;' % klassname
        print >> self.fd, '    zval* zval_this;'
        print >> self.fd, '    PhpGObjectPtr *cvt_this;'
        if self.is_object(m_type):
            print >> self.fd, '    PhpGObjectPtr *self;'
        elif m_type == 'GList*' and m_options.get('elem_type') == 'char*':
            print >> self.fd, '    GList* item = NULL;'
        print >> self.fd, ''
        print >> self.fd, '''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zval_this) == FAILURE) {
        RETURN_FALSE;
    }

    ZEND_FETCH_RESOURCE(cvt_this, PhpGObjectPtr *, &zval_this, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
    this = (%s*)cvt_this->obj;
''' % (klassname)

        if self.is_object(m_type):
            print >> self.fd, '    if (this->%s != NULL) {' % m_name
            print >> self.fd, '        return_c_value = g_object_ref(this->%s);' % m_name
            print >> self.fd, '    }'
        else:
            print >> self.fd, '    return_c_value = this->%s;' % m_name

        self.return_value(m_type, m_options)

        print >> self.fd, '}'
        print >> self.fd, ''


    def generate_setter(self, klassname, m_type, m_name, m_options):
        if m_type == 'GList*' and m_options.get('elem_type') != 'char*':
            print >> sys.stderr, 'E: GList argument : %s of %s, with type : %s' % (m_name, klassname, m_options.get('elem_type'))
            return

        function_name = '%s_%s_set' % (klassname, format_attribute(m_name))
        function_name = '%s_%s_set' % (klassname, utils.format_as_camelcase(m_name))
        print >> self.fd, '''PHP_FUNCTION(%s)
{''' % function_name
        self.functions_list.append(function_name)

        print >> self.fd, '    %s* this;' % klassname
        print >> self.fd, '    zval* zval_this;'
        print >> self.fd, '    PhpGObjectPtr *cvt_this;'

        # FIXME: This bloc should be factorised
        parse_tuple_format = ''
        parse_tuple_args = []
        arg_type = m_type
        arg_name = m_name
        arg_options = m_options
        if arg_type in ('char*', 'const char*', 'gchar*', 'const gchar*'):
            arg_type = arg_type.replace('const ', '')
            parse_tuple_format += 's'
            parse_tuple_args.append('&%s_str, &%s_len' % (arg_name, arg_name))
            print >> self.fd, '    %s %s_str = NULL;' % ('char*', arg_name)
            print >> self.fd, '    %s %s_len = 0;' % ('int', arg_name)
        elif arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums:
            parse_tuple_format += 'l'
            parse_tuple_args.append('&%s' % arg_name)
            print >> self.fd, '    %s %s;' % ('long', arg_name)
        # Must also handle lists of Objects
        elif arg_type == 'GList*' and arg_options.get('elem_type') == 'char*':
            parse_tuple_format += 'a'
            parse_tuple_args.append('&zval_%s' % arg_name)
            print >> self.fd, '    %s zval_%s;' % ('zval*', arg_name)
            print >> self.fd, '    %s %s_data;' % ('zval**', arg_name)
            print >> self.fd, '    %s %s_hashtable;' % ('HashTable*', arg_name)
            print >> self.fd, '    %s %s_pointer;' % ('HashPosition', arg_name)
            print >> self.fd, '    %s %s_size;' % ('int', arg_name)
        else:
            parse_tuple_format += 'r'
            parse_tuple_args.append('&zval_%s' % arg_name)
            print >> self.fd, '    %s zval_%s = NULL;' % ('zval*', arg_name)
            print >> self.fd, '    %s cvt_%s = NULL;' % ('PhpGObjectPtr*', arg_name)

        if parse_tuple_args:
            parse_tuple_arg = parse_tuple_args[0]
        else:
            print >> self.fd, '}'
            print >> self.fd, ''
            return

        print >> self.fd, ''
        print >> self.fd, '''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r%s", &zval_this, %s) == FAILURE) {
        return;
    }
''' % (parse_tuple_format, parse_tuple_arg)

        # Get 'this' object
        print >> self.fd, '''\
    ZEND_FETCH_RESOURCE(cvt_this, PhpGObjectPtr *, &zval_this, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
    this = (%s*)cvt_this->obj;
''' % klassname

        # Set new value
        if parse_tuple_format == 'l':
            print >> self.fd, '    this->%s = %s;' % (m_name, m_name)
        elif parse_tuple_format == 's':
            print >> self.fd, '    if (this->%s) {' % m_name
            print >> self.fd, '        efree(this->%s);' % m_name
            print >> self.fd, '    }'
            print >> self.fd, '    if (%s_str && strcmp(%s_str, "") != 0) {' % (m_name, m_name)
            print >> self.fd, '        this->%s = estrndup(%s_str, %s_len);' % (m_name, m_name, m_name)
            print >> self.fd, '    } else {'
            print >> self.fd, '        this->%s = NULL;' % m_name
            print >> self.fd, '    }'
        elif parse_tuple_format == 'a':
            if m_options.get('elem_type') == 'char*':
                print >> self.fd, '''
    if (this->%(name)s) {
        /* free existing list */
        g_list_foreach(this->%(name)s, (GFunc)g_free, NULL);
        g_list_free(this->%(name)s);
    }
    %(name)s_hashtable = Z_ARRVAL_P(zval_%(name)s);
    %(name)s_size = zend_hash_num_elements(%(name)s_hashtable);
    for (zend_hash_internal_pointer_reset_ex(%(name)s_hashtable, &%(name)s_pointer);
            zend_hash_get_current_data_ex(%(name)s_hashtable, (void**) &%(name)s_data, &%(name)s_pointer) == SUCCESS;
            zend_hash_move_forward_ex(%(name)s_hashtable, &%(name)s_pointer)) {
        if (Z_TYPE_PP(%(name)s_data) == IS_STRING) {
            this->%(name)s = g_list_append(this->%(name)s, estrndup(Z_STRVAL_PP(%(name)s_data), Z_STRLEN_PP(%(name)s_data)));
        }
    }
''' % { 'name': m_name }
        elif parse_tuple_format == 'r':
            print >> self.fd, '    ZEND_FETCH_RESOURCE(cvt_%s, PhpGObjectPtr *, &zval_%s, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);' % (m_name, m_name)
            print >> self.fd, '    this->%s = (%s)cvt_%s->obj;' % (m_name, m_type, m_name)

        print >> self.fd, '}'
        print >> self.fd, ''

    def generate_members(self, c):
        for m_type, m_name, m_options in c.members:
            self.generate_getter(c.name, m_type, m_name, m_options)
            self.generate_setter(c.name, m_type, m_name, m_options)

    def generate_functions_list(self):
        print >> self.fd, '''\
static function_entry lasso_functions[] = {'''
        for m in self.functions_list:
            print >> self.fd, '    PHP_FE(%s, NULL)' % m
        print >> self.fd, '''\
    {NULL, NULL, NULL}
};
'''

    def generate_footer(self):
        print >> self.fd, '''\
zend_module_entry lasso_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    PHP_LASSO_EXTNAME,
    lasso_functions,
    PHP_MINIT(lasso),
    PHP_MSHUTDOWN(lasso),
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    PHP_LASSO_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
'''

