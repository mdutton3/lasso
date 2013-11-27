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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

import sys
import os

from utils import *

class WrapperSource:
    def __init__(self, binding_data, fd):
        self.binding_data = binding_data
        self.fd = fd
        self.functions_list = []
        self.src_dir = os.path.dirname(__file__)

    def is_object(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*', 'GList*', 'GHashTable*', 'GType',
                'xmlNode*', 'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

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
        self.functions_list.append('lasso_init')
        self.functions_list.append('lasso_shutdown')

        print >> self.fd, '''\
/* this file has been generated automatically; do not edit */
'''

        print >> self.fd, open(os.path.join(self.src_dir,'wrapper_source_top.c')).read()

        for h in self.binding_data.headers:
            print >> self.fd, '#include <%s>' % h
        print >> self.fd, ''

        print >> self.fd, '''\
PHP_MINIT_FUNCTION(lasso)
{
    le_lasso_server = zend_register_list_destructors_ex(php_gobject_generic_destructor, NULL, PHP_LASSO_SERVER_RES_NAME, module_number);
    lasso_init();
'''

    def generate_constants(self):
        print >> self.fd, '    /* Constants (both enums and defines) */'
        for c in self.binding_data.constants:
            if c[0] == 'i':
                print >> self.fd, '    REGISTER_LONG_CONSTANT("%s", %s, CONST_CS|CONST_PERSISTENT);' % (c[1], c[1])
            elif c[0] == 's':
                print >> self.fd, '    REGISTER_STRING_CONSTANT("%s", (char*) %s, CONST_CS|CONST_PERSISTENT);' % (c[1], c[1])
            elif c[0] == 'b':
                print >> self.fd, '''\
#ifdef %s
    REGISTER_LONG_CONSTANT("%s", 1, CONST_CS|CONST_PERSISTENT);
#else
    REGISTER_LONG_CONSTANT("%s", 0, CONST_CS|CONST_PERSISTENT);
#endif''' % (c[1], c[1], c[1])
            else:
                print >> sys.stderr, 'E: unknown constant type: %r' % c[0]
        print >> self.fd, ''

    def generate_middle(self):
        print >> self.fd, '''\
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(lasso)
{
    lasso_shutdown();
    return SUCCESS;
}

'''

    def set_zval(self, zval_name, c_variable, type, free = False):
        '''Emit code to set a zval* of name zval_name, from the value of the C variable called c_variable type, type.
        '''
        # first we free the previous value
        p = (zval_name, c_variable)
        q = { 'zval_name' : zval_name, 'c_variable' : c_variable }
        print >> self.fd, '    zval_dtor(%s);' % zval_name
        if is_pointer(type):
            print >> self.fd, '    if (! %s) {' % c_variable
            print >> self.fd, '       ZVAL_NULL(%s);' % zval_name
            print >> self.fd, '    } else {'
        if is_int(type, self.binding_data):
            print >> self.fd, '    ZVAL_LONG(%s, %s);' % p
        elif is_boolean(type):
            print >> self.fd, '    ZVAL_BOOL(%s, %s);' % p
        elif is_cstring(type):
            print >> self.fd, '    ZVAL_STRING(%s, (char*)%s, 1);' % p
            if free and not is_const(type):
                print >> self.fd, 'g_free(%s)' % c_variable
        elif arg_type(type) == 'xmlNode*':
            print >> self.fd, '''\
    {
        char* xmlString = get_string_from_xml_node(%(c_variable)s);
        if (xmlString) {
            ZVAL_STRING(%(zval_name)s, xmlString, 0);
        } else {
            ZVAL_NULL(%(zval_name)s);
        }
    }
''' % q
        elif is_glist(type):
            elem_type = make_arg(element_type(type))
            if not arg_type(elem_type):
                raise Exception('unknown element-type: ' + repr(type))
            if is_cstring(elem_type):
                function = 'set_array_from_list_of_strings'
                free_function = 'free_glist(&%(c_variable)s, (GFunc)free);'
            elif arg_type(elem_type).startswith('xmlNode'):
                function = 'set_array_from_list_of_xmlnodes'
                free_function = 'free_glist(&%(c_variable)s, (GFunc)xmlFree);'
            elif is_object(elem_type):
                function = 'set_array_from_list_of_objects'
                free_function = 'g_list_free(%(c_variable)s);'
            else:
                raise Exception('unknown element-type: ' + repr(type))
            print >> self.fd, '     %s((GList*)%s, &%s);' % (function, c_variable, zval_name)
            if free:
                print >> self.fd, '   ', free_function % q
        elif is_object(type):
            print >> self.fd, '''\
    if (G_IS_OBJECT(%(c_variable)s)) {
        PhpGObjectPtr *obj = PhpGObjectPtr_New(G_OBJECT(%(c_variable)s));
        ZEND_REGISTER_RESOURCE(%(zval_name)s, obj, le_lasso_server);
    } else {
        ZVAL_NULL(%(zval_name)s);
    }''' % q
            if free:
                print >> self.fd, '''\
    if (%(c_variable)s) {
        g_object_unref(%(c_variable)s); // If constructor ref is off by one'
    }''' % q

        else:
            raise Exception('unknown type: ' + repr(type) + unconstify(arg_type(type)))
        if is_pointer(type):
            print >> self.fd, '    }'



    def return_value(self, arg, free = False):
        if arg is None:
            return

        if is_boolean(arg):
            print >> self.fd, '    RETVAL_BOOL(return_c_value);'
        elif is_int(arg, self.binding_data):
            print >> self.fd, '    RETVAL_LONG(return_c_value);'
        elif is_cstring(arg):
            print >> self.fd, '''\
    if (return_c_value) {
        RETVAL_STRING((char*)return_c_value, 1);
    } else {
        RETVAL_NULL();
    }'''
            if free:
                print >> self.fd, '    free(return_c_value);'
        elif is_xml_node(arg):
            print >> self.fd, '''\
    {
        char* xmlString = get_string_from_xml_node(return_c_value);
        if (xmlString) {
            RETVAL_STRING(xmlString, 0);
        } else {
            RETVAL_NULL();
        }
    }
'''
            if free:
                print >> self.fd, '    lasso_release_xml_node(return_c_value);'
        elif is_glist(arg):
            el_type = element_type(arg)
            if is_cstring(el_type):
                print >> self.fd, '''\
    set_array_from_list_of_strings((GList*)return_c_value, &return_value);
'''
                if free:
                    print >> self.fd, '    lasso_release_list_of_strings(return_c_value);'
            elif is_xml_node(el_type):
                print >> self.fd, '''\
    set_array_from_list_of_xmlnodes((GList*)return_c_value, &return_value);
'''
                if free or is_transfer_full(arg):
                    print >> self.fd, '    lasso_release_list_of_xml_node(return_c_value);'
            elif is_object(el_type):
                print >> self.fd, '''\
    set_array_from_list_of_objects((GList*)return_c_value, &return_value);
'''
                if free:
                    print >> self.fd, '    lasso_release_list_of_gobjects(return_c_value);'
            else:
                raise Exception('cannot return value for %s' % (arg,))
        elif is_hashtable(arg):
            el_type = element_type(arg)
            if is_object(el_type):
                print >> self.fd, '''\
    set_array_from_hashtable_of_objects(return_c_value, &return_value);
'''
            else:
                if not is_cstring(arg):
                    print >>sys.stderr, 'W: %s has no explicit string annotation' % (arg,)
                print >> self.fd, '''\
    set_array_from_hashtable_of_strings(return_c_value, &return_value);
'''
        elif is_object(arg):
            print >> self.fd, '''\
    if (return_c_value) {
        PhpGObjectPtr *self;
        self = PhpGObjectPtr_New(G_OBJECT(return_c_value));
        ZEND_REGISTER_RESOURCE(return_value, self, le_lasso_server);
    } else {
        RETVAL_NULL();
    }'''
            if free:
                print >> self.fd, '    lasso_release_gobject(return_c_value);'
        else:
            raise Exception('cannot return value for %s' % (arg,))

    def generate_function(self, m):
        if m.name in ('lasso_init','lasso_shutdown'):
            return
        if m.rename:
            name = m.rename
        else:
            name = m.name
        self.functions_list.append(name)
        print >> self.fd, '''PHP_FUNCTION(%s)
{''' % name
        parse_tuple_format = []
        parse_tuple_args = []
        for arg in m.args:
            if is_out(arg):
                print >> self.fd, '   zval *php_out_%s = NULL;' % arg_name(arg)
                print >> self.fd, '   %s %s;' % (var_type(arg), arg_name(arg))
                parse_tuple_format.append('z!')
                parse_tuple_args.append('&php_out_%s' % arg_name(arg))
            elif is_cstring(arg):
                parse_tuple_format.append('s!')
                parse_tuple_args.append('&%s_str, &%s_len' % (arg_name(arg), arg_name(arg)))
                print >> self.fd, '    %s %s = NULL;' % ('char*', arg_name(arg))
                print >> self.fd, '    %s %s_str = NULL;' % ('char*', arg_name(arg))
                print >> self.fd, '    %s %s_len = 0;' % ('int', arg_name(arg))
            elif is_int(arg, self.binding_data) or is_boolean(arg):
                parse_tuple_format.append('l')
                parse_tuple_args.append('&%s' % arg_name(arg))
                print >> self.fd, '    %s %s;' % ('long', arg_name(arg))
            elif is_time_t_pointer(arg):
                parse_tuple_format.append('l')
                parse_tuple_args.append('&%s' % (arg_name(arg),))
                print >>self.fd,  '    time_t %s = 0;' % (arg_name(arg),)
            elif is_xml_node(arg):
                parse_tuple_format.append('s!')
                parse_tuple_args.append('&%s_str, &%s_len' % (arg_name(arg), arg_name(arg)))
                print >> self.fd, '    %s %s = NULL;' % ('xmlNode*', arg_name(arg))
                print >> self.fd, '    %s %s_str = NULL;'  % ('char*', arg_name(arg))
                print >> self.fd, '    %s %s_len = 0;' % ('int', arg_name(arg))
            elif is_glist(arg):
                parse_tuple_format.append('a!')
                parse_tuple_args.append('&zval_%s' % arg_name(arg))
                print >> self.fd, '    %s zval_%s = NULL;' % ('zval*', arg_name(arg))
                print >> self.fd, '    %s %s = NULL;' % ('GList*', arg_name(arg))
            elif is_object(arg):
                parse_tuple_format.append('r')
                parse_tuple_args.append('&zval_%s' % arg_name(arg))
                print >> self.fd, '    %s %s = NULL;' % (arg_type(arg), arg_name(arg))
                print >> self.fd, '    %s zval_%s = NULL;' % ('zval*', arg_name(arg))
                print >> self.fd, '    %s cvt_%s = NULL;' % ('PhpGObjectPtr*', arg_name(arg))
            else:
                raise Exception('Unsupported type %s %s' % (arg, m))

        if m.return_type:
            print >> self.fd, '    %s return_c_value;' % m.return_type
        if m.return_type is not None and self.is_object(m.return_arg):
            print >> self.fd, '    G_GNUC_UNUSED PhpGObjectPtr *self;'
        print >> self.fd, ''

        parse_tuple_args = ', '.join(parse_tuple_args)
        if parse_tuple_args:
            parse_tuple_args = ', ' + parse_tuple_args

        print >> self.fd, '''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "%s"%s) == FAILURE) {
        RETURN_FALSE;
    }
''' % (''.join(parse_tuple_format), parse_tuple_args)

        for f, arg in zip(parse_tuple_format, m.args):
            if is_out(arg):
                continue
            elif is_xml_node(arg):
                print >> self.fd, '''\
        %(name)s = get_xml_node_from_string(%(name)s_str);''' % {'name': arg[1]}
            elif f.startswith('s'):
                print >> self.fd, '''\
        %(name)s = %(name)s_str;''' % {'name': arg[1]}
            elif f.startswith('r'):
                print >> self.fd, '    ZEND_FETCH_RESOURCE(cvt_%s, PhpGObjectPtr *, &zval_%s, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);' % (arg[1], arg[1])
                print >> self.fd, '    %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1])
            elif f.startswith('a'):
                el_type = element_type(arg)
                if is_cstring(el_type):
                    print >> self.fd, '    %(name)s = get_list_from_array_of_strings(zval_%(name)s);' % {'name': arg[1]}
                elif is_object(el_type):
                    print >> self.fd, '    %(name)s = get_list_from_array_of_objects(zval_%(name)s);' % {'name': arg[1]}
                else:
                    print >> sys.stderr, 'E: In %(function)s arg %(name)s is of type GList<%(elem)s>' % { 'function': m.name, 'name': arg[1], 'elem': el_type }
            elif f == 'l':
                pass
            else:
                raise Exception('%s format inconnu' % f)


        if m.return_type is not None:
            print >> self.fd, '    return_c_value = ',
            if 'new' in m.name:
                print >> self.fd, '(%s)' % m.return_type,
        else:
            print >> self.fd, '   ',
        def special(x):
            if is_time_t_pointer(x):
                return '%(name)s ? &%(name)s : NULL' % { 'name': arg_name(x) }
            else:
                return ref_name(x)
        print >> self.fd, '%s(%s);' % (m.name, ', '.join([special(x) for x in m.args]))
        # Free the converted arguments

        for f, arg in zip(parse_tuple_format, m.args):
            argtype, argname, argoptions = arg
            if is_out(arg):
                # export the returned variable
                free = is_transfer_full(unref_type(arg))
                self.set_zval('php_out_%s' % argname, argname, unref_type(arg), free = free)
                pass
            elif argtype == 'xmlNode*':
                print >> self.fd, '    xmlFree(%s);' % argname
            elif f.startswith('a'):
                el_type = element_type(arg)
                if is_cstring(el_type):
                    print >> self.fd, '    if (%(name)s) {' % { 'name': arg[1] }
                    print >> self.fd, '        free_glist(&%(name)s,(GFunc)free);' % { 'name': arg[1] }
                    print >> self.fd, '    }'

        try:
            self.return_value(m.return_arg, is_transfer_full(m.return_arg, default=True))
        except:
            raise Exception('Cannot return value for function %s' % m)

        print >> self.fd, '}'
        print >> self.fd, ''

    def generate_members(self, c):
        for m in c.members:
            self.generate_getter(c, m)
            self.generate_setter(c, m)

    def generate_getter(self, c, m):
        klassname = c.name
        name = arg_name(m)
        type = arg_type(m)

        function_name = '%s_%s_get' % (klassname, format_as_camelcase(name))
        print >> self.fd, '''PHP_FUNCTION(%s)
{''' % function_name
        self.functions_list.append(function_name)

        print >> self.fd, '    %s return_c_value;' % type
        print >> self.fd, '    %s* this;' % klassname
        print >> self.fd, '    zval* zval_this;'
        print >> self.fd, '    PhpGObjectPtr *cvt_this;'
        print >> self.fd, ''
        print >> self.fd, '''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zval_this) == FAILURE) {
        RETURN_FALSE;
    }

    ZEND_FETCH_RESOURCE(cvt_this, PhpGObjectPtr *, &zval_this, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
    this = (%s*)cvt_this->obj;
''' % (klassname)
        print >> self.fd, '    return_c_value = (%s)this->%s;' % (type, name)
        self.return_value(m)
        print >> self.fd, '}'
        print >> self.fd, ''

    def generate_setter(self, c, m):
        klassname = c.name
        name = arg_name(m)
        type = arg_type(m)
        function_name = '%s_%s_set' % (klassname, format_as_camelcase(name))
        print >> self.fd, '''PHP_FUNCTION(%s)
{''' % function_name
        self.functions_list.append(function_name)

        print >> self.fd, '    %s* this;' % klassname
        print >> self.fd, '    zval* zval_this;'
        print >> self.fd, '    PhpGObjectPtr *cvt_this;'

        # FIXME: This bloc should be factorised
        parse_tuple_format = ''
        parse_tuple_args = []
        if is_cstring(m) or is_xml_node(m):
            # arg_type = arg_type.replace('const ', '')
            parse_tuple_format += 's'
            parse_tuple_args.append('&%s_str, &%s_len' % (name, name))
            print >> self.fd, '    %s %s_str = NULL;' % ('char*', name)
            print >> self.fd, '    %s %s_len = 0;' % ('int', name)
        elif is_int(m, self.binding_data) or is_boolean(m):
            parse_tuple_format += 'l'
            parse_tuple_args.append('&%s' % name)
            print >> self.fd, '    %s %s;' % ('long', name)
        # Must also handle lists of Objects
        elif is_glist(m) or is_hashtable(m):
            parse_tuple_format += 'a'
            parse_tuple_args.append('&zval_%s' % name)
            print >> self.fd, '    %s zval_%s;' % ('zval*', name)
        elif is_object(m):
            parse_tuple_format += 'r'
            parse_tuple_args.append('&zval_%s' % name)
            print >> self.fd, '    %s zval_%s = NULL;' % ('zval*', name)
            print >> self.fd, '    %s cvt_%s = NULL;' % ('PhpGObjectPtr*', name)
        else:
            raise Exception('Cannot make a setter for %s.%s' % (c,m))

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
        d = { 'name': name, 'type': type }
        if is_int(m, self.binding_data) or is_boolean(m):
            print >> self.fd, '    this->%s = %s;' % (name, name)
        elif is_cstring(m):
            print >> self.fd, '    lasso_assign_string(this->%(name)s, %(name)s_str);' % d
        elif is_xml_node(m):
            print >> self.fd, '    lasso_assign_new_xml_node(this->%(name)s, get_xml_node_from_string(%(name)s_str));' % d
        elif is_glist(m):
            el_type = element_type(m)
            if is_cstring(el_type):
                print >> self.fd, '    lasso_assign_new_list_of_strings(this->%(name)s, get_list_from_array_of_strings(zval_%(name)s));' % d
            elif is_xml_node(el_type):
                print >> self.fd, '    lasso_assign_new_list_of_xml_node(this->%(name)s, get_list_from_array_of_xmlnodes(zval_%(name)s))' % d
            elif is_object(el_type):
                print >> self.fd, '    lasso_assign_new_list_of_gobjects(this->%(name)s, get_list_from_array_of_objects(zval_%(name)s));' % d
            else:
                raise Exception('Cannot create C setter for %s.%s' % (c,m))
        elif is_hashtable(m):
            el_type = element_type(m)
            print >> self.fd, '''\
        {
            GHashTable *oldhash = this->%(name)s;''' % d
            if is_object(el_type):
                print >>self.fd, '            this->%(name)s = get_hashtable_from_array_of_objects(zval_%(name)s);' % d
            else:
                print >>self.fd, '            this->%(name)s = get_hashtable_from_array_of_strings(zval_%(name)s);' % d
            print >> self.fd, '            g_hash_table_destroy(oldhash);'
            print >> self.fd, '        }'
        elif is_object(m):
            print >> self.fd, '    ZEND_FETCH_RESOURCE(cvt_%(name)s, PhpGObjectPtr*, &zval_%(name)s, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);' % d
            print >> self.fd, '    lasso_assign_gobject(this->%(name)s, cvt_%(name)s->obj);' % d

        print >> self.fd, '}'
        print >> self.fd, ''

    def generate_functions_list(self):
        print >> self.fd, '''\
static zend_function_entry lasso_functions[] = {'''
        for m in self.functions_list:
            print >> self.fd, '    PHP_FE(%s, NULL)' % m
        print >> self.fd, '''\
    {NULL, NULL, NULL, 0, 0}
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

