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
import os
import utils

module_file = '_lasso.c'
header_file = '_lasso.h'
php_file = 'lasso.php'

def zval(name):
    return 'zval_' + name

class Binding:
    def __init__(self, binding_data):
        self.binding_data = binding_data
        self.module_fd = open(module_file, 'w')
        self.header_fd = open(header_file, 'w')
        self.php_fd = open(php_file, 'w')
        self.functions_list = list()
        self.shiftcount = 0

    def __del__(self):
        close(self.module_fd)
        close(self.header_fd)
        close(self.php_fd)

# Helper code
    def is_object(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*', 'GList*', 'GHashTable*',
                'xmlNode*', 'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

    def error(self,str):
        print >> sys.stderr, 'E: %s' % str

    def warning(self,str):
        print >> sys.stderr, 'W: %s' % str

    def printshift(self,fd):
        if self.shiftcount:
            print >> fd, (self.shiftcount-1)*' ',

    def shift(self):
        self.shiftcount += 4

    def unshift(self):
        self.shiftcount -= 4

    def module(self,str):
        self.printshift(self.module_fd)
        print >> self.module_fd, str

    def php(self,str):
        self.printshift(self.php_fd)
        print >> self.php_fd, str

    def header(self,str):
        self.printshift(self.header_fd)
        print >> self.header_fd, str

    def define(self,name,value):
        self.header('#define %s %s' % (name,value))

    def include(self, str):
        self.module('#include "%s"' % str)

    def function(self, function_name):
        self.functions_list.append(function_name)
        self.module('PHP_FUNCTION(%s)' % function_name)

    def open(self):
        self.module('{')
        self.shift()

    def close(self):
        self.unshift()
        self.module('}')

    def ret(self, value):
        self.module('return %s;' % value)

    def success(self):
        self.ret('SUCCESS')
    
    def declare_zval(self, name):
        self.declare('zval*', zval(name))
    
    def declare(self, type, name):
        self.module('%s %s;' % (type, name))

    def comment(self, str):
        self.module('/* %s */' % str)

    def free(self,name):
        self.module('free(%s);' % name)

    def get_php_list(self, name, element_type):
        self.comment(' Get php list %s of type %s from %s ' % (name, element_type, zval(name)))


    def get_php_hashtable(self, name, element_type):
        self.comment(' Get php hashtable %s of type %s from %s ' % (name, element_type, zval(name)))

    def get_object(self, name, type):
        self.comment(' Get object %s of type %s from php resource %s ' % (name, type, zval(name)))

    def parse_format_arg(self, arg):
        type, name, options = arg
        ret = ''
        if type == 'gboolean':
            ret =  'b'
            return ret
        elif type in ['int', 'gint'] + self.binding_data.enums:
            ret =  'l'
            return ret
        elif type in ('char*', 'gchar*','const char*','const gchar*'):
            ret =  's'
        elif type == 'xmlNode*':
            ret =  's'
        elif type == 'GList*':
            ret =  'a'
        elif type == 'GHashTable*':
            ret =  'a'
        elif self.is_object(type):
            ret =  'r'
        else:
            self.error('%s of type %s has no format string' % (name, type))
        if options.get('nonull') == None and ret:
            ret += '!'
        return ret
    
    def generate_parse_args(self, arg):
        type, name, options = arg
        ret = ''
        if type == 'gboolean' or type in ['int', 'gint'] + self.binding_data.enums:
            self.declare(type, name)
            return list(name)
        elif type in ('char*', 'gchar*','const char*','const gchar*'):
            self.declare('char*', name)
            self.declare('int', name + '_len')
            return (name, name + '_len')
        elif type == 'xmlNode*':
            self.declare('char*', name + '_str')
            self.declare('int', name + '_len')
            self.declare('xmlNode*', name)
            return (name + '_str', name + '_len')
        elif type == 'GList*' or type == 'GHashTable*' or self.is_object(type):
            self.declare_zval(name)
            self.declare(type, name)
            return list(zval(name))
        else:
            self.error('%s of type %s has no format arg' % (name, type))
        return list()

    def method_prologue(self, klass, name, args = list()):
        self.function(name)
        self.open()
        self.declare('int', 'zpp_ret')
        self.declare(klass.name + '*', 'a_gobject')
        this = zval('this')
        self.declare_zval('this')
        # this should not be null
        parse_format = 'r'
        parse_args = list(this)
        for arg in args:
            type, name, options = arg
            # Create parse_format
            parse_format += self.parse_format_char(arg)
            # Allocate variables
            parse_args = self.generate_parse_args(arg)
        # Call parse parameters
        self.module('zpp_ret = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "%s", %s)' % (parse_format, ','.join([ "&" + x for x in parse_args])))
        self.module('if (zpp_ret == Failure)')
        self.open()
        self.module('RETURN_NULL();');
        self.close()
        # Convert the resource
        self.module('ZEND_FETCH_RESOURCE(a_gobject, %s*, &%s, -1, PHP_LASSO_GOBJECT_RES_NAME, le_lasso_gobject);')
        self.module('if (a_gobject == NULL)')
        self.open()
        self.module('zend_error(E_WARNING, "Calling a method on a null GObject resource, big problem");')
        self.module('RETURN_NULL();');
        self.close()
        for arg in args:
            type, name, options = arg
            if type == 'gboolean' and type in ['int', 'gint'] + self.binding_data.enums and type in ('char*', 'gchar*','const char*','const gchar*'):
                pass
            elif type == 'xmlNode*':
                self.module('get_xml_node_from_string(&%(name)s,%(name)s_str);' % { 'name': name })
            elif type == 'GList*':
                self.get_php_list(name, options.get('element_type'))
            elif type == 'GHashTable*':
                self.get_php_hashtable(name, options.get('element_type'))
            elif self.is_object(type):
                self.get_object(name, type)

    def method_epilogue(self, args = list()):
        for arg in args:
            type, name, options = arg 
            type, name, options = arg
            if type == 'gboolean' and type in ['int', 'gint'] + self.binding_data.enums and type in ('char*', 'gchar*','const char*','const gchar*'):
                pass
            elif type == 'xmlNode*':
                self.free_xmldoc(name)
            elif type == 'GList*':
                self.free_glist(name, options.get('element_type'))
            elif type == 'GHashTable*':
                self.free_hashtable(name, options.get('element_type'))
            elif self.is_object(type):
                pass
            else:
                self.error('Bizarre type %s' % type)
        self.close()

    def generate_module_dummy_function(self, name):
        self.module(name)
        self.open()
        self.success()
        self.close()
# Type helpers
    def update_c_value(self, left, right, type, options, free = True, copy = False):
        if type == 'gboolean' and type in ['int', 'gint'] + self.binding_data.enums:
            self.module('%s = %s;' % (left, right))
            return

        if free:
            self.module('if (%s)' % left)
            self.open()
            self.free(left, type, options)
            self.close()
        pat = ''
        if type in ('char*','gchar*') and copy:
            pat = '%s = g_strdup(%s);'
        else:
            par = '%s = %s;'
        self.module(pat % (left, right))
        
    def return_c_value(self, type, name, options = dict()):
        if type is None:
            return

        if type == 'gboolean':
            self.module('RETVAL_BOOL(%s);' % name)
            return
        elif type in ['int', 'gint'] + self.binding_data.enums:
            self.module('RETVAL_LONG(%s);' % name)
            return
        # Pointer types
        self.module('if (%s)' % name)
        self.open()
        if type in ('char*', 'gchar*','const char*','const gchar*'):
            if options.get('eallocated') == 1:
                self.module('RETVAL_STRING(%s,0);' % name)
            else:
                self.module('RETVAL_STRING(%s,1);' % name)
        elif type == 'xmlNode*':
            self.open()
            self.declare('char*','xmlString')
            self.module('xmlString = get_string_from_xml_node(%s);' % name)
            self.return_c_value('char*','xmlString', { 'eallocated': 1 })
            self.close()
        elif type == 'GList*':
            pass
        elif type == 'GHashTable*':
            pass
        elif self.is_object(type):
            self.module('ZVAL_REGISTER_RESOURCE(return_value, %s, le_lasso_gobject);' % name)
        else:
            self.error('%s of type %s is not returnable' % (name, type))
        self.close()
        self.module('else')
        self.open()
        self.module('RETVAL_NULL();')
        self.close()
#
        
    def generate(self):
        self.generate_php()
        self.generate_module()
        # Must be called last because generate_module
        # compute self.functions_lists
        # that is needed by generate_header_functions_list
        self.generate_header()

# Generation of the C header
    # Generate the lasso.h file
    def generate_header(self):
        self.header('/* this file has been generated automatically; do not edit */')
        self.header('#ifndef PHP_LASSO_H')
        self.header('#define PHP_LASSO_H 1')
        self.header('')
        self.define('PHP_LASSO_EXTNAME', '"lasso"')
        self.define('PHP_LASSO_VERSION', '"2.1.1"')
        self.define('PHP_LASSO_GOBJECT_RES_NAME', 'LassoGObject')
        self.header('PHP_MINIT_FUNCTION(lasso);')
        self.header('PHP_MSHUTDOWN_FUNCTION(lasso);')
        self.header('PHP_RINIT_FUNCTION(lasso);')
        self.generate_header_functions_list()
        self.generate_header_globals()
        # Declare GObject resource destructor
        self.header('static void php_lasso_gobject_dtor(zend_rsrc_list_entry *rsrc TSRMLS_DC);')
        self.header('extern zend_module_entry lasso_module_entry;')
        self.define('phpext_lasso_ptr','&lasso_module_entry')
        self.header('#endif')

    def generate_header_functions_list(self):
        for m in self.functions_list:
            self.header('PHP_FUNCTION(%s);' % m)
        self.header('')

    def generate_header_globals(self):
        self.header('#ifdef ZTS')
        self.header('#include "TSRM.h"')
        self.header('#endif')
        self.header('')
        self.header('ZEND_BEGIN_MODULE_GLOBALS(lasso)')
        self.header('ZEND_END_MODULE_GLOBALS(lasso)')
        self.header('')
        self.header('#ifdef ZTS')
        self.header('#define LASSO_G(v) TSRMG(lasso_globals_id, zend_lasso_globals *, v)')
        self.header('#else')
        self.header('#define LASSO_G(v) (lasso_globals.v)')
        self.header('#endif')

# Generation of the C module
    def generate_module(self):
        self.generate_module_top()
        self.generate_module_minit()
        self.generate_module_gobject_resource_dtor()
        self.generate_functions()
        self.generate_getters_setters()
        self.generate_function_declarations()
        self.generate_module_entry()
        self.generate_module_php_ini()

    def generate_module_top(self):
        self.include('php.h')
        self.include('php_ini.h')
        self.include(header_file)
        self.include('lasso_php4_helper.c')
        self.module('ZEND_DECLARE_MODULE_GLOBALS(lasso)')
        self.module('')
        self.module('#if COMPILE_DL_LASSO')
        self.module('ZEND_GET_MODULE(lasso) ')
        self.module('#endif')
        self.module('/* GObject resource type */')
        self.module('int le_lasso_gobject');

    def generate_module_entry(self):
        self.module('zend_module_entry lasso_module_entry = {')
        self.module('#if ZEND_MODULE_API_NO >= 20010901')
        self.module('    STANDARD_MODULE_HEADER,')
        self.module('#endif')
        self.module('    PHP_HELLO_WORLD_EXTNAME,')
        self.module('    lasso_functions,')
        self.module('    PHP_MINIT(lasso),')
        self.module('    PHP_MSHUTDOWN(lasso),')
        self.module('    PHP_RINIT(lasso), /* Request init function */')
        self.module('    PHP_RSHUTDOWN(lasso) , /* Request shutdown function/ ')
        self.module('    NULL, /* PHP info function */')
        self.module('#if ZEND_MODULE_API_NO >= 20010901')
        self.module('    PHP_HELLO_WORLD_VERSION,')
        self.module('#endif')
        self.module('    STANDARD_MODULE_PROPERTIES')
        self.module('};')

    def generate_module_gobject_resource_dtor(self):
        self.module('static void php_lasso_gobject_dtor(zend_rsrc_list_entry *rsrc TSRMLS_DC) {')
        self.shift()
        self.module('GObject *a_gobject;')
        self.module('g_object_unref((GObject*)rsrc->ptr);')
        self.unshift()
        self.module('}')

    def generate_module_php_ini(self):
        self.module('PHP_INI_BEGIN()')
        self.shift()
        # self.module('PHP_INI_ENTRY("lasso.greeting", "Hello World", PHP_INI_ALL, NULL)')
        # self.module('STD_PHP_INI_ENTRY("lasso.direction", "1", PHP_INI_ALL, OnUpdateBool, direction, zend_lasso_globals, lasso_globals)')
        self.unshift()
        self.module('PHP_INI_END()')

    def generate_module_minit(self):
        self.module('PHP_MINIT(lasso)')
        self.open()
        self.generate_module_minit_constants()
        # Init globals
        # self.module('LASSO_G(autocoin) = 1;')
        self.generate_module_minit_register_resources()
        self.success()
        self.close()

    def generate_module_minit_constants(self):
        self.module('/* Constants (both enums and defines) */')
        mapping = { 
            'i': 'REGISTER_LONG_CONSTANT("%(name)s", %(name)s, CONST_CS|CONST_PERSISTENT);',
            's': 'REGISTER_STRING_CONSTANT("%(name)s", %(name)s, CONST_CS|CONST_PERSISTENT);',
            'b': '''\
#ifdef %(name)s
    REGISTER_LONG_CONSTANT("%(name)s", 1, CONST_CS|CONST_PERSISTENT);
#else
    REGISTER_LONG_CONSTANT("%(name)s", 0, CONST_CS|CONST_PERSISTENT);
#endif''' }
        for c in self.binding_data.constants:
            constant_type, constant_name = c
            if constant_type in mapping:
                self.module(mapping[constant_type] % { 'name': constant_name } )
            else:
                self.error('unknown constant type "%s"' % constant_type)


    def generate_module_minit_register_resources(self):
        self.module('le_lasso_gobject = zend_register_list_destructors_ex(php_lasso_gobject_dtor, NULL, PHP_LASSO_GOBJECT_RES_NAME, module_number);')


    def generate_module_mshutdown(self):
        self.generate_module_dummy_function('PHP_MSHUTDOWN(lasso)')

    def generate_module_rinit(self):
        self.generate_module_dummy_function('PHP_RINIT(lasso)')
    
    def generate_module_rshutdown(self):
        self.generate_module_dummy_function('PHP_RSHUTDOWN(lasso)')

    def generate_getters_setters(self):
        for klass in self.binding_data.structs:
            for member in klass.members:
                self.generate_getter(klass, member)
                self.generate_getter(klass, member)

    def function_name(self, klass, member, suffix):
        type, name, options = member
        return '%s_%s_%s' % (klass.name, utils.format_as_camelcase(name), suffix)
    def getter_function_name(self, klass, member):
        return self.function_name(klass, member, 'get')
    def setter_function_name(self, klass, member):
        return self.function_name(klass, member, 'set')
    def generate_getter(self, klass, member):
        type, name, options = member
        elem_type = options.get('elem_type')
        function_name = self.getter_function_name(klass, member)
        self.method_prologue(klass, function_name)
        self.return_c_value(type, 'a_gobject->' + name, options)
        self.method_epilogue()

    def generate_setter(self, klass, member):
        type, name, options = member
        elem_type = options.get('elem_type')
        function_name = self.setter_function_name(klass, member)
        self.method_prologue(klass, function_name, list(member))
        # Affectation: a_gobject->name = name
        self.update_c_value('a_gobject->' + name, name, type, options, True, True)
        self.method_epilogue()

    def generate_functions(self):
        pass

    def generate_function(self):
        pass

    def generate_function_arg_decl(self):
        pass

    def generate_function_call(self):
        pass

    def generate_function_arg_free(self):
        pass

    def genreate_function_return(self):
        pass

    def generate_function_declarations(self):
        pass

    def generate_function_declaration(self):
        pass

# Generate of the PHP file
    def generate_php(self):
        pass

    def generate_php_objects(self):
        pass

    def generate_php_getters_setters(self):
        pass

    def generate_methods(self):
        pass

    def generate_exception_classes(self):
        pass

    def generate_exception_class(self):
        pass

