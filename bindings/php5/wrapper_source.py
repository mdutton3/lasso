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
import six

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

        six.print_('''\
/* this file has been generated automatically; do not edit */
''', file=self.fd)

        six.print_(open(os.path.join(self.src_dir,'wrapper_source_top.c')).read(), file=self.fd)

        for h in self.binding_data.headers:
            six.print_('#include <%s>' % h, file=self.fd)
        six.print_('', file=self.fd)

        six.print_('''\
PHP_MINIT_FUNCTION(lasso)
{
    le_lasso_server = zend_register_list_destructors_ex(php_gobject_generic_destructor, NULL, PHP_LASSO_SERVER_RES_NAME, module_number);
    lasso_init();
''', file=self.fd)

    def generate_constants(self):
        six.print_('    /* Constants (both enums and defines) */', file=self.fd)
        for c in self.binding_data.constants:
            if c[0] == 'i':
                six.print_('    REGISTER_LONG_CONSTANT("%s", %s, CONST_CS|CONST_PERSISTENT);' % (c[1], c[1]), file=self.fd)
            elif c[0] == 's':
                six.print_('    REGISTER_STRING_CONSTANT("%s", (char*) %s, CONST_CS|CONST_PERSISTENT);' % (c[1], c[1]), file=self.fd)
            elif c[0] == 'b':
                six.print_('''\
#ifdef %s
    REGISTER_LONG_CONSTANT("%s", 1, CONST_CS|CONST_PERSISTENT);
#else
    REGISTER_LONG_CONSTANT("%s", 0, CONST_CS|CONST_PERSISTENT);
#endif''' % (c[1], c[1], c[1]), file=self.fd)
            else:
                six.print_('E: unknown constant type: %r' % c[0], file=sys.stderr)
        six.print_('', file=self.fd)

    def generate_middle(self):
        six.print_('''\
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(lasso)
{
    lasso_shutdown();
    return SUCCESS;
}

''', file=self.fd)

    def set_zval(self, zval_name, c_variable, type, free = False):
        '''Emit code to set a zval* of name zval_name, from the value of the C variable called c_variable type, type.
        '''
        # first we free the previous value
        p = (zval_name, c_variable)
        q = { 'zval_name' : zval_name, 'c_variable' : c_variable }
        six.print_('    zval_dtor(%s);' % zval_name, file=self.fd)
        if is_pointer(type):
            six.print_('    if (! %s) {' % c_variable, file=self.fd)
            six.print_('       ZVAL_NULL(%s);' % zval_name, file=self.fd)
            six.print_('    } else {', file=self.fd)
        if is_int(type, self.binding_data):
            six.print_('    ZVAL_LONG(%s, %s);' % p, file=self.fd)
        elif is_boolean(type):
            six.print_('    ZVAL_BOOL(%s, %s);' % p, file=self.fd)
        elif is_cstring(type):
            six.print_('    ZVAL_STRING(%s, (char*)%s, 1);' % p, file=self.fd)
            if free and not is_const(type):
                six.print_('g_free(%s)' % c_variable, file=self.fd)
        elif arg_type(type) == 'xmlNode*':
            six.print_('''\
    {
        char* xmlString = get_string_from_xml_node(%(c_variable)s);
        if (xmlString) {
            ZVAL_STRING(%(zval_name)s, xmlString, 0);
        } else {
            ZVAL_NULL(%(zval_name)s);
        }
    }
''' % q, file=self.fd)
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
            six.print_('     %s((GList*)%s, &%s);' % (function, c_variable, zval_name), file=self.fd)
            if free:
                six.print_('   ', free_function % q, file=self.fd)
        elif is_object(type):
            six.print_('''\
    if (G_IS_OBJECT(%(c_variable)s)) {
        PhpGObjectPtr *obj = PhpGObjectPtr_New(G_OBJECT(%(c_variable)s));
        ZEND_REGISTER_RESOURCE(%(zval_name)s, obj, le_lasso_server);
    } else {
        ZVAL_NULL(%(zval_name)s);
    }''' % q, file=self.fd)
            if free:
                six.print_('''\
    if (%(c_variable)s) {
        g_object_unref(%(c_variable)s); // If constructor ref is off by one'
    }''' % q, file=self.fd)

        else:
            raise Exception('unknown type: ' + repr(type) + unconstify(arg_type(type)))
        if is_pointer(type):
            six.print_('    }', file=self.fd)



    def return_value(self, arg, free = False):
        if arg is None:
            return

        if is_boolean(arg):
            six.print_('    RETVAL_BOOL(return_c_value);', file=self.fd)
        elif is_int(arg, self.binding_data):
            six.print_('    RETVAL_LONG(return_c_value);', file=self.fd)
        elif is_cstring(arg):
            six.print_('''\
    if (return_c_value) {
        RETVAL_STRING((char*)return_c_value, 1);
    } else {
        RETVAL_NULL();
    }''', file=self.fd)
            if free:
                six.print_('    free(return_c_value);', file=self.fd)
        elif is_xml_node(arg):
            six.print_('''\
    {
        char* xmlString = get_string_from_xml_node(return_c_value);
        if (xmlString) {
            RETVAL_STRING(xmlString, 0);
        } else {
            RETVAL_NULL();
        }
    }
''', file=self.fd)
            if free:
                six.print_('    lasso_release_xml_node(return_c_value);', file=self.fd)
        elif is_glist(arg):
            el_type = element_type(arg)
            if is_cstring(el_type):
                six.print_('''\
    set_array_from_list_of_strings((GList*)return_c_value, &return_value);
''', file=self.fd)
                if free:
                    six.print_('    lasso_release_list_of_strings(return_c_value);', file=self.fd)
            elif is_xml_node(el_type):
                six.print_('''\
    set_array_from_list_of_xmlnodes((GList*)return_c_value, &return_value);
''', file=self.fd)
                if free or is_transfer_full(arg):
                    six.print_('    lasso_release_list_of_xml_node(return_c_value);', file=self.fd)
            elif is_object(el_type):
                six.print_('''\
    set_array_from_list_of_objects((GList*)return_c_value, &return_value);
''', file=self.fd)
                if free:
                    six.print_('    lasso_release_list_of_gobjects(return_c_value);', file=self.fd)
            else:
                raise Exception('cannot return value for %s' % (arg,))
        elif is_hashtable(arg):
            el_type = element_type(arg)
            if is_object(el_type):
                six.print_('''\
    set_array_from_hashtable_of_objects(return_c_value, &return_value);
''', file=self.fd)
            else:
                if not is_cstring(arg):
                    print >>sys.stderr, 'W: %s has no explicit string annotation' % (arg,)
                six.print_('''\
    set_array_from_hashtable_of_strings(return_c_value, &return_value);
''', file=self.fd)
        elif is_object(arg):
            six.print_('''\
    if (return_c_value) {
        PhpGObjectPtr *self;
        self = PhpGObjectPtr_New(G_OBJECT(return_c_value));
        ZEND_REGISTER_RESOURCE(return_value, self, le_lasso_server);
    } else {
        RETVAL_NULL();
    }''', file=self.fd)
            if free:
                six.print_('    lasso_release_gobject(return_c_value);', file=self.fd)
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
        six.print_('''PHP_FUNCTION(%s)
{''' % name, file=self.fd)
        parse_tuple_format = []
        parse_tuple_args = []
        for arg in m.args:
            if is_out(arg):
                six.print_('   zval *php_out_%s = NULL;' % arg_name(arg), file=self.fd)
                six.print_('   %s %s;' % (var_type(arg), arg_name(arg)), file=self.fd)
                parse_tuple_format.append('z!')
                parse_tuple_args.append('&php_out_%s' % arg_name(arg))
            elif is_cstring(arg):
                parse_tuple_format.append('s!')
                parse_tuple_args.append('&%s_str, &%s_len' % (arg_name(arg), arg_name(arg)))
                six.print_('    %s %s = NULL;' % ('char*', arg_name(arg)), file=self.fd)
                six.print_('    %s %s_str = NULL;' % ('char*', arg_name(arg)), file=self.fd)
                six.print_('    %s %s_len = 0;' % ('int', arg_name(arg)), file=self.fd)
            elif is_int(arg, self.binding_data) or is_boolean(arg):
                parse_tuple_format.append('l')
                parse_tuple_args.append('&%s' % arg_name(arg))
                six.print_('    %s %s;' % ('long', arg_name(arg)), file=self.fd)
            elif is_time_t_pointer(arg):
                parse_tuple_format.append('l')
                parse_tuple_args.append('&%s' % (arg_name(arg),))
                print >>self.fd,  '    time_t %s = 0;' % (arg_name(arg),)
            elif is_xml_node(arg):
                parse_tuple_format.append('s!')
                parse_tuple_args.append('&%s_str, &%s_len' % (arg_name(arg), arg_name(arg)))
                six.print_('    %s %s = NULL;' % ('xmlNode*', arg_name(arg)), file=self.fd)
                six.print_('    %s %s_str = NULL;'  % ('char*', arg_name(arg)), file=self.fd)
                six.print_('    %s %s_len = 0;' % ('int', arg_name(arg)), file=self.fd)
            elif is_glist(arg):
                parse_tuple_format.append('a!')
                parse_tuple_args.append('&zval_%s' % arg_name(arg))
                six.print_('    %s zval_%s = NULL;' % ('zval*', arg_name(arg)), file=self.fd)
                six.print_('    %s %s = NULL;' % ('GList*', arg_name(arg)), file=self.fd)
            elif is_object(arg):
                parse_tuple_format.append('r')
                parse_tuple_args.append('&zval_%s' % arg_name(arg))
                six.print_('    %s %s = NULL;' % (arg_type(arg), arg_name(arg)), file=self.fd)
                six.print_('    %s zval_%s = NULL;' % ('zval*', arg_name(arg)), file=self.fd)
                six.print_('    %s cvt_%s = NULL;' % ('PhpGObjectPtr*', arg_name(arg)), file=self.fd)
            else:
                raise Exception('Unsupported type %s %s' % (arg, m))

        if m.return_type:
            six.print_('    %s return_c_value;' % m.return_type, file=self.fd)
        if m.return_type is not None and self.is_object(m.return_arg):
            six.print_('    G_GNUC_UNUSED PhpGObjectPtr *self;', file=self.fd)
        six.print_('', file=self.fd)

        parse_tuple_args = ', '.join(parse_tuple_args)
        if parse_tuple_args:
            parse_tuple_args = ', ' + parse_tuple_args

        six.print_('''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "%s"%s) == FAILURE) {
        RETURN_FALSE;
    }
''' % (''.join(parse_tuple_format), parse_tuple_args), file=self.fd)

        for f, arg in zip(parse_tuple_format, m.args):
            if is_out(arg):
                continue
            elif is_xml_node(arg):
                six.print_('''\
        %(name)s = get_xml_node_from_string(%(name)s_str);''' % {'name': arg[1]}, file=self.fd)
            elif f.startswith('s'):
                six.print_('''\
        %(name)s = %(name)s_str;''' % {'name': arg[1]}, file=self.fd)
            elif f.startswith('r'):
                six.print_('    ZEND_FETCH_RESOURCE(cvt_%s, PhpGObjectPtr *, &zval_%s, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);' % (arg[1], arg[1]), file=self.fd)
                six.print_('    %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1]), file=self.fd)
            elif f.startswith('a'):
                el_type = element_type(arg)
                if is_cstring(el_type):
                    six.print_('    %(name)s = get_list_from_array_of_strings(zval_%(name)s);' % {'name': arg[1]}, file=self.fd)
                elif is_object(el_type):
                    six.print_('    %(name)s = get_list_from_array_of_objects(zval_%(name)s);' % {'name': arg[1]}, file=self.fd)
                else:
                    six.print_('E: In %(function)s arg %(name)s is of type GList<%(elem)s>' % { 'function': m.name, 'name': arg[1], 'elem': el_type }, file=sys.stderr)
            elif f == 'l':
                pass
            else:
                raise Exception('%s format inconnu' % f)


        if m.return_type is not None:
            six.print_('    return_c_value = ', file=self.fd)
            if 'new' in m.name:
                six.print_('(%s)' % m.return_type, file=self.fd)
        else:
            six.print_('   ', file=self.fd)
        def special(x):
            if is_time_t_pointer(x):
                return '%(name)s ? &%(name)s : NULL' % { 'name': arg_name(x) }
            else:
                return ref_name(x)
        six.print_('%s(%s);' % (m.name, ', '.join([special(x) for x in m.args])), file=self.fd)
        # Free the converted arguments

        for f, arg in zip(parse_tuple_format, m.args):
            argtype, argname, argoptions = arg
            if is_out(arg):
                # export the returned variable
                free = is_transfer_full(unref_type(arg))
                self.set_zval('php_out_%s' % argname, argname, unref_type(arg), free = free)
                pass
            elif argtype == 'xmlNode*':
                six.print_('    xmlFree(%s);' % argname, file=self.fd)
            elif f.startswith('a'):
                el_type = element_type(arg)
                if is_cstring(el_type):
                    six.print_('    if (%(name)s) {' % { 'name': arg[1] }, file=self.fd)
                    six.print_('        free_glist(&%(name)s,(GFunc)free);' % { 'name': arg[1] }, file=self.fd)
                    six.print_('    }', file=self.fd)

        try:
            self.return_value(m.return_arg, is_transfer_full(m.return_arg, default=True))
        except:
            raise Exception('Cannot return value for function %s' % m)

        six.print_('}', file=self.fd)
        six.print_('', file=self.fd)

    def generate_members(self, c):
        for m in c.members:
            self.generate_getter(c, m)
            self.generate_setter(c, m)

    def generate_getter(self, c, m):
        klassname = c.name
        name = arg_name(m)
        type = arg_type(m)

        function_name = '%s_%s_get' % (klassname, format_as_camelcase(name))
        six.print_('''PHP_FUNCTION(%s)
{''' % function_name, file=self.fd)
        self.functions_list.append(function_name)

        six.print_('    %s return_c_value;' % type, file=self.fd)
        six.print_('    %s* this;' % klassname, file=self.fd)
        six.print_('    zval* zval_this;', file=self.fd)
        six.print_('    PhpGObjectPtr *cvt_this;', file=self.fd)
        six.print_('', file=self.fd)
        six.print_('''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zval_this) == FAILURE) {
        RETURN_FALSE;
    }

    ZEND_FETCH_RESOURCE(cvt_this, PhpGObjectPtr *, &zval_this, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
    this = (%s*)cvt_this->obj;
''' % (klassname), file=self.fd)
        six.print_('    return_c_value = (%s)this->%s;' % (type, name), file=self.fd)
        self.return_value(m)
        six.print_('}', file=self.fd)
        six.print_('', file=self.fd)

    def generate_setter(self, c, m):
        klassname = c.name
        name = arg_name(m)
        type = arg_type(m)
        function_name = '%s_%s_set' % (klassname, format_as_camelcase(name))
        six.print_('''PHP_FUNCTION(%s)
{''' % function_name, file=self.fd)
        self.functions_list.append(function_name)

        six.print_('    %s* this;' % klassname, file=self.fd)
        six.print_('    zval* zval_this;', file=self.fd)
        six.print_('    PhpGObjectPtr *cvt_this;', file=self.fd)

        # FIXME: This bloc should be factorised
        parse_tuple_format = ''
        parse_tuple_args = []
        if is_cstring(m) or is_xml_node(m):
            # arg_type = arg_type.replace('const ', '')
            parse_tuple_format += 's'
            parse_tuple_args.append('&%s_str, &%s_len' % (name, name))
            six.print_('    %s %s_str = NULL;' % ('char*', name), file=self.fd)
            six.print_('    %s %s_len = 0;' % ('int', name), file=self.fd)
        elif is_int(m, self.binding_data) or is_boolean(m):
            parse_tuple_format += 'l'
            parse_tuple_args.append('&%s' % name)
            six.print_('    %s %s;' % ('long', name), file=self.fd)
        # Must also handle lists of Objects
        elif is_glist(m) or is_hashtable(m):
            parse_tuple_format += 'a'
            parse_tuple_args.append('&zval_%s' % name)
            six.print_('    %s zval_%s;' % ('zval*', name), file=self.fd)
        elif is_object(m):
            parse_tuple_format += 'r'
            parse_tuple_args.append('&zval_%s' % name)
            six.print_('    %s zval_%s = NULL;' % ('zval*', name), file=self.fd)
            six.print_('    %s cvt_%s = NULL;' % ('PhpGObjectPtr*', name), file=self.fd)
        else:
            raise Exception('Cannot make a setter for %s.%s' % (c,m))

        if parse_tuple_args:
            parse_tuple_arg = parse_tuple_args[0]
        else:
            six.print_('}', file=self.fd)
            six.print_('', file=self.fd)
            return

        six.print_('', file=self.fd)
        six.print_('''\
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r%s", &zval_this, %s) == FAILURE) {
        return;
    }
''' % (parse_tuple_format, parse_tuple_arg), file=self.fd)

        # Get 'this' object
        six.print_('''\
    ZEND_FETCH_RESOURCE(cvt_this, PhpGObjectPtr *, &zval_this, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
    this = (%s*)cvt_this->obj;
''' % klassname, file=self.fd)

        # Set new value
        d = { 'name': name, 'type': type }
        if is_int(m, self.binding_data) or is_boolean(m):
            six.print_('    this->%s = %s;' % (name, name), file=self.fd)
        elif is_cstring(m):
            six.print_('    lasso_assign_string(this->%(name)s, %(name)s_str);' % d, file=self.fd)
        elif is_xml_node(m):
            six.print_('    lasso_assign_new_xml_node(this->%(name)s, get_xml_node_from_string(%(name)s_str));' % d, file=self.fd)
        elif is_glist(m):
            el_type = element_type(m)
            if is_cstring(el_type):
                six.print_('    lasso_assign_new_list_of_strings(this->%(name)s, get_list_from_array_of_strings(zval_%(name)s));' % d, file=self.fd)
            elif is_xml_node(el_type):
                six.print_('    lasso_assign_new_list_of_xml_node(this->%(name)s, get_list_from_array_of_xmlnodes(zval_%(name)s))' % d, file=self.fd)
            elif is_object(el_type):
                six.print_('    lasso_assign_new_list_of_gobjects(this->%(name)s, get_list_from_array_of_objects(zval_%(name)s));' % d, file=self.fd)
            else:
                raise Exception('Cannot create C setter for %s.%s' % (c,m))
        elif is_hashtable(m):
            el_type = element_type(m)
            six.print_('''\
        {
            GHashTable *oldhash = this->%(name)s;''' % d, file=self.fd)
            if is_object(el_type):
                six.print_('            this->%(name)s = get_hashtable_from_array_of_objects(zval_%(name)s);' % d, file=self.fd)
            else:
                six.print_('            this->%(name)s = get_hashtable_from_array_of_strings(zval_%(name)s);' % d, file=self.fd)
            six.print_('            g_hash_table_destroy(oldhash);', file=self.fd)
            six.print_('        }', file=self.fd)
        elif is_object(m):
            six.print_('    ZEND_FETCH_RESOURCE(cvt_%(name)s, PhpGObjectPtr*, &zval_%(name)s, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);' % d, file=self.fd)
            six.print_('    lasso_assign_gobject(this->%(name)s, cvt_%(name)s->obj);' % d, file=self.fd)

        six.print_('}', file=self.fd)
        six.print_('', file=self.fd)

    def generate_functions_list(self):
        six.print_('''\
static zend_function_entry lasso_functions[] = {''', file=self.fd)
        for m in self.functions_list:
            six.print_('    PHP_FE(%s, NULL)' % m, file=self.fd)
        six.print_('''\
    {NULL, NULL, NULL, 0, 0}
};
''', file=self.fd)

    def generate_footer(self):
        six.print_('''\
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
''', file=self.fd)

