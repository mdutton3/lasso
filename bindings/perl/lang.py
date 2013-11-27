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

import os
import os.path
import sys
import re
import textwrap
from utils import *

class Output(object):
    def __init__(self, filename, indent = 4):
        self.fd = open(filename, 'w')
        self.indent_stack = [0]
        self.indent_size = indent

    def pn(self, s = ''):
        print >> self.fd, (' ' * self.indent_stack[-1]) + s

    def p(self, s = ''):
        print >>self.fd, s,

    def close(self):
        self.fd.close()

    def indent(self, c = None):
        if not c:
            c = self.indent_size
        self.indent_stack.append(c)

    def unindent(self):
        self.indent_stack.pop()

package_top = '''package Lasso;
use strict;
use warnings;

require XSLoader;
XSLoader::load('Lasso');
'''

class Binding:
    xs = None
    pm = None
    typemap = None
    binding_data = None

    def __init__(self, binding_data):
        self.binding_data = binding_data
        self.src_dir = os.path.dirname(__file__)
        self.xs = Output('Lasso.xs')
        self.pm = Output('Lasso.pm')
        self.typemap = Output('typemap')

    def file_content(self, filename):
        return file(os.path.join(self.src_dir, filename)).read()

    def generate(self):
        # Generate XS
        self.generate_typemap()
        self.generate_xs_header()
        self.generate_xs_constants()
        self.generate_xs_functions()
        self.generate_xs_footer()

        # Generate PM
        self.generate_pm_header()


        # Generate 
        self.generate_exceptions()
        for clss in self.binding_data.structs:
            self.generate_class(clss)

    def generate_typemap(self):
        self.typemap.pn('TYPEMAP')
        self.typemap.pn('''
string_or_null\tT_STRING_OR_NULL
string_non_null\tT_STRING_NON_NULL
const gchar *\tT_PV
gchar *\tT_PV
gboolean\tT_IV
const LassoProvider *\tT_GOBJECT_WRAPPER
xmlNode*\tT_XMLNODE
const xmlNode*\tT_XMLNODE
GList_string\tT_GLIST_STRING
GList_xmlnode\tT_GLIST_XMLNODE
GList_gobject\tT_GLIST_GOBJECT
GList_string_const\tT_GLIST_STRING
GList_gobject_const\tT_GLIST_GOBJECT
const GList*\tT_GLIST_STRING
GHashTable*\tT_PTRREF

''')
        # Map integer types
        for int in [ 'lasso_error_t', 'int', 'gint', 'long', 'glong'] + self.binding_data.enums:
            self.typemap.pn('%-30s T_IV' % int)

        # Map object types
        for clss in self.binding_data.structs:
            self.typemap.pn('%-30s T_GOBJECT_WRAPPER' % (clss.name + '*'))
            self.typemap.pn('const %-30s T_GOBJECT_WRAPPER' % (clss.name + '*'))

        # Create INPUT & OUTPUT maps
        self.typemap.p(self.file_content('typemap-in'))
        self.typemap.p(self.file_content('typemap-out'))

    def generate_pm_header(self):
        # Lasso.pm
        self.pm.p(package_top)

        for struct in self.binding_data.structs:
            if struct.name != 'LassoNode':
                self.pm.pn('package Lasso::%s;' % struct.name[5:])
                self.pm.pn('our @ISA = qw(Lasso::%s);' % struct.parent[5:])
                self.pm.pn()

    def generate_xs_header(self):
        '''Generate header of XS file'''
        self.xs.pn('''
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <stdio.h>

#if defined(__GNUC__)
#  define lasso_log(level, filename, line, function, format, args...) \
        g_log("Lasso", level, "%s:%i:%s" format, filename, line, function, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define lasso_log(level, format, line, function, ...)  \
        g_log("Lasso", leve, "%s:%i:%s" format, filename, line, function, __VA_ARGS__)
#else
static inline void lasso_log(GLogLevelFlags level, const char *filename,
    int line, const char *function, const char *format, ...)
{
	va_list ap;
	char s[1024];
	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
    g_log("Lasso", level, "%s:%i:%s %s", filename, line, function, s);
}
#define lasso_log lasso_log
#endif

#include "gobject_handling.c"
#include "glist_handling.c"
#include "ghashtable_handling.c"


#define lasso_assign_simple(a,b) a = b;

typedef char* string_non_null;
typedef char* string_or_null;
typedef GList* GList_string;
typedef GList* GList_gobject;
typedef GList* GList_xmlnode;
typedef const GList* GList_string_const;
typedef const GList* GList_gobject_const;

/* #include "ppport.h" */''')
        for h in self.binding_data.headers:
            self.xs.pn('#include <%s>' % h)
        self.xs.pn('''
MODULE = Lasso PACKAGE = Lasso::Node

INCLUDE: LassoNode.xs
''')
        self.xs.pn('MODULE = Lasso		PACKAGE = Lasso      PREFIX = lasso_ ')
        self.xs.pn()
        self.xs.pn('PROTOTYPES: ENABLE')
        self.xs.pn()

    def generate_xs_constants(self):
        '''Generate a function which can return an int from a string'''
        self.xs.pn('''BOOT:
{
    SV *ct;
    HV *stash;

    init_perl_lasso();
    stash = gv_stashpv("Lasso::Constants", 1);''')
        self.xs.indent()
        for constant in self.binding_data.constants:
            type, name = constant
            perl_name = name[6:]
            if False:
                self.xs.pn('ct = get_sv("Lasso::Constants::%s", TRUE | GV_ADDMULTI);' % perl_name)
                if type == 'i':
                    self.xs.pn('sv_setiv(ct, %s);' % name)
                elif type == 's':
                    self.xs.pn('sv_setpv(ct, %s);' % name)
                elif type == 'b': # only one case LASSO_WSF_ENABLED
                    self.xs.unindent()
                    self.xs.pn('''#ifdef %s
        sv_setiv(ct, 1);
    #else
        sv_setiv(ct, 0);
    #endif''' % name)
                    self.xs.indent()
                else:
                    raise Exception('Unknown constant type: type: "%s" name: "%s"' % (type,name))
                self.xs.pn('SvREADONLY_on (ct);')
            else:
                if type == 'i':
                    self.xs.pn('ct = newSViv(%s);' % name)
                elif type == 's':
                    self.xs.pn('ct = newSVpv((char*)%s, 0);' % name)
                elif type == 'b': # only one case LASSO_WSF_ENABLED
                    self.xs.unindent()
                    self.xs.pn('''#ifdef %s
        ct = newSViv(1);
#else
        ct = newSViv(0);
#endif''' % name)
                    self.xs.indent()
                self.xs.pn('newCONSTSUB(stash, "%s", ct);' % perl_name)
        self.xs.unindent()
        self.xs.pn('}')


    def generate_exceptions(self):
        '''Generate class for exceptions

        Generate a generic Error which can call lasso_strerror and a mapping
        from rc code to Exception class
        '''

        for c in self.binding_data.constants:
            m = re.match(r'LASSO_(\w+)_ERROR_(.*)', c[1])
            if not m:
                continue
            cat, detail = m.groups()

    def generate_xs_footer(self):
        '''Generate footer of XS file'''
        pass

    def generate_class(self, clss):
        klassname = clss.name
        pass

    def default_value(self, arg):
        default = arg_default(arg)
        if default[0] == 'b':
            return default[2:]
        elif default[0] == 'c':
            return default[2:]
        else:
            raise Exception('Unknown default value for %s' % (arg,))

    def generate_xs_function(self, func, prefix = None):
        cleanup = []
        name = func.name
        self.xs.pn()
        if not func.return_type or not is_glist(func.return_arg):
            self.xs.pn(func.return_type or 'void')
        elif is_glist(func.return_arg):
            try:
                self.xs.pn(self.glist_type(func.return_arg))
            except:
                print >>sys.stderr, 'failed', func.return_arg, func
                raise
        self.xs.p(name + '(')
        arg_list = []
        out_list = []
        arg_names = []
        if name.endswith('_new'):
            arg_list.append('char *cls')
            arg_names.append('cls')
        for arg in func.args:
            decl = ''
            aname = arg_name(arg)
            if is_out(arg):
                arg_names.append(aname)
                if not is_int(arg, self.binding_data) and is_object(arg):
                    decl = unconstify(arg_type(arg))[:-1] + ' &' + aname + ' = NO_INIT'
                    out_list.append(aname)
                else:
                    raise Exception('Out arg of type: %s is not supported' % (arg,))
            else:
                if is_cstring(arg):
                    if is_optional(arg):
                        decl = 'string_or_null %s' % aname
                    else:
                        decl = 'string_non_null %s' % aname
                elif not is_glist(arg):
                    decl = '%s %s' % (unconstify(arg_type(arg)), aname)
                else:
                    decl = '%s %s' % (self.glist_type(arg), aname)
                if is_optional(arg):
                    if arg_default(arg):
                        arg_names.append(aname + ' = ' + self.default_value(arg))
                    else:
                        if is_cstring(arg) or is_glist(arg) or is_xml_node(arg) or is_object(arg):
                            arg_names.append(aname + ' = NULL')
                        else:
                            raise Exception('Do not know what to do for optional: %s' % arg)
                else:
                    arg_names.append(aname)
            arg_list.append(decl)
            # Cleanup code, for by-reference arguments
            if is_glist(arg) and not is_transfer_full(arg):
                    cleanup.append(self.release_list(arg_name(arg), arg))
            if is_xml_node(arg) and not is_transfer_full(arg):
                    cleanup.append('lasso_release_xml_node(%s)' % arg_name(arg))
            if is_hashtable(arg):
                raise Exception("No cleanup code generation for GHashTable")
        self.xs.p(','.join(arg_names))
        self.xs.pn(')')
        for decl in arg_list:
            self.xs.pn('  %s' % (decl,))
        if name.endswith('_new'):
            self.xs.pn('  INIT:')
            self.xs.pn('    cls = NULL;')
            self.xs.pn('  C_ARGS:')
            self.xs.pn('    ' + ', '.join([arg_name(arg) for arg in func.args]))
        elif prefix and not func.name.startswith(prefix + 'new'):
            self.xs.pn('  INIT:')
            self.xs.pn('    check_gobject((GObject*)%(first_arg)s, %(gtype)s);' % {
                'first_arg': arg_name(func.args[0]),
                'gtype': prefix + 'get_type()' 
                } )
        if out_list:
            self.xs.pn('  INIT:')
            for o in out_list:
                self.xs.pn('    %s = NULL;' % o)
            self.xs.pn('  OUTPUT:')
            for o in out_list:
                self.xs.pn('    %s' % o)
        need_prototype = False
        for x in func.args:
            if is_glist(x):
                need_prototype = True
            elif is_hashtable(x):
                raise Exception("Dont know how to generate prototype for a hashtable argument")
        if need_prototype:
            self.xs.p('PROTOTYPE: ')
            optional = False
            proto = []
            if name.endswith('_new'):
                proto.append('$')
            for arg in func.args:
                if is_optional(arg) and not optional:
                    proto.append(';')
                    optional = True
                if is_glist(arg):
                    proto.append('\\@')
                else:
                    proto.append('$')
            self.xs.pn(''.join(proto))
        if '_new_' in name:
            self.xs.pn('   CODE:')
            self.xs.pn('       RETVAL = (%(type)s)%(name)s(%(args)s);' %
                    { 'name': name,
                      'type': func.return_type,
                      'args': ' ,'.join([arg_name(arg) for arg in func.args]) })
            self.xs.pn('''   OUTPUT:
         RETVAL''')
            cleanup.append('lasso_unref(RETVAL);')
        elif func.return_type and is_object(func.return_type) and not is_int(func.return_type, self.binding_data) and func.return_owner:
            cleanup.append('lasso_unref(RETVAL);')
        elif is_rc(func.return_arg):
            if name == 'lasso_check_version':
                cleanup.append('if (RETVAL != 1)')
            cleanup.append('gperl_lasso_error(RETVAL);')
        # Output cleanup code
        if cleanup:
            self.xs.pn('  CLEANUP:')
            self.xs.indent()
            for cl in cleanup:
                self.xs.pn(cl)
            self.xs.unindent()

    def generate_xs_getter_setter(self, struct, member):
        name = arg_name(member)
        type = arg_type(member)
        el_type = element_type(member)
        # Simple getter/setter
        if not is_glist(member) and not is_hashtable(member):
            self.xs.pn('''
%(rtype)s
%(field)s(%(clss)s* obj, %(rtype)s value = 0)
    CODE:
        if (items > 1) {
            %(assignment)s
            XSRETURN(0);
        } else {
            RETVAL = obj->%(field)s;
        }
    OUTPUT:
        RETVAL

            ''' % { 'rtype': type, 'field': name, 'clss': struct.name, 'assignment': self.assign_type(member, 'obj->%s' % arg_name(member), 'value', struct) })
        elif is_glist(member):
             self.xs.pn('''
%(rtype)s
%(field)s(%(clss)s* obj, ...)
    PREINIT:
        int i = 1;
    CODE:
        if (items > 1) {
            %(release)s
            for (; i < items; i++) {
                %(el_type)s data;
                data = (%(el_type)s)%(convert)s;
                if (! data) {
                    %(release)s
                    croak("an element cannot be converted to an %(el_type)s");
                }
                %(push)s(obj->%(field)s, data);
            }
            XSRETURN(0);
        } else {
            RETVAL = obj->%(field)s;
        }
    OUTPUT:
        RETVAL

            ''' % { 'rtype': self.glist_type(member), 
                'field': name, 
                'clss': struct.name,
                'el_type': self.element_type2real_type(element_type(member)),
                'push': self.push_macro(member),
                'convert': self.convert_function('ST(i)', member),
                'release': self.release_list('obj->' + arg_name(member), member),
                })
        elif is_hashtable(member):
            if is_object(element_type(member)):
                kind = "objects"
            else:
                kind = "strings"
            self.xs.pn('''
HV*
%(field)s(%(clss)s* obj, ...)
    PROTOTYPE:
        $;\%%
    CODE:
        if (items > 1) { /* setter */
            if (SvTYPE(ST(1)) != SVt_RV || ! SvTYPE(SvRV(ST(1))) != SVt_PVHV) {
                sv_dump(ST(1));
                croak("Lasso::%(klass)s::%(field)s takes a reference to a hash as argument");
            }
            set_hash_of_%(kind)s(&obj->%(field)s, (HV*)SvRV(ST(1)));
        }
        RETVAL = get_hash_of_%(kind)s(obj->%(field)s);
        sv_2mortal((SV*)RETVAL);
    OUTPUT:
        RETVAL
''' % { 'kind': kind,
            'field': name, 
            'clss': struct.name,
            'klass': struct.name[5:]
                })

    def starify(self, str):
        if '*' in str:
            return str
        else:
            return str + '*'

    def glist_type(self, member):
        x = self.element_type_lookup(member, { 'string': 'GList_string', 'xml_node': 'GList_xmlnode', 'gobject': 'GList_gobject'})
        if is_const(member):
            return x + '_const'
        return x

    def element_type_lookup(self, member, lookup_table):
        if not is_glist(member):
            raise Exception('calling release_list on %s' % member)
        type = element_type(member)
        if is_cstring(type):
            return lookup_table['string']
        elif is_xml_node(type):
            return lookup_table['xml_node']
        elif is_object(type):
            return lookup_table['gobject']
        else:
            raise Exception('Do not know how to release GList<%s>' % type)
        return '%s(%s->%s);' % (macro, what, arg_name(member))


    def release_list(self, what, member):
        if not is_glist(member):
            raise Exception('calling release_list on %s' % member)
        type = element_type(member)
        if is_cstring(type):
            macro = 'lasso_release_list_of_strings'
        elif is_xml_node(type):
            macro = 'lasso_release_list_of_xml_node'
        elif is_object(type):
            macro = 'lasso_release_list_of_gobjects'
        else:
            raise Exception('Do not know how to release GList<%s>' % type)
        return '%s(%s);' % (macro, what)

    def convert_function(self, what, member):
        if not is_glist(member):
            raise Exception('calling release_list on %s' % member)
        type = element_type(member)
        if is_cstring(type):
            macro = 'SvPV_nolen'
        elif is_xml_node(type):
            macro = 'pv_to_xmlnode'
        elif is_object(type):
            macro = 'gperl_get_object'
        else:
            raise Exception('Do not know how to release GList<%s>' % type)
        return '%s(%s)' % (macro, what)

    def push_macro(self, member):
        if not is_glist(member):
            raise Exception('calling release_list on %s' % member)
        type = element_type(member)
        if is_cstring(type):
            macro = 'lasso_list_add_string'
        elif is_xml_node(type):
            macro = 'lasso_list_add_new_xml_node'
        elif is_object(type):
            macro = 'lasso_list_add_gobject'
        else:
            raise Exception('Do not know how to push to GList<%s>' % type)
        return macro

    def assign_type(self, arg, to, fr, struct = None):
        type = arg_type(arg)
        el_type = element_type(arg)
        name = arg_name
        if is_int(arg, self.binding_data):
            macro = 'lasso_assign_simple'
        elif is_cstring(arg):
            macro = 'lasso_assign_string'
        elif is_xml_node(arg):
            macro = 'lasso_assign_xml_node'
        elif is_glist(arg):
            if not el_type:
                raise Exception('%s has no element type %s' % (arg, struct))
            if is_cstring(el_type):
                macro = 'lasso_assign_list_of_strings'
            elif is_xml_node(el_type):
                macro = 'lasso_assign_simple' # FIXME
            elif is_object(el_type):
                macro = 'lasso_assign_list_of_gobjects'
            else:
                raise Exception('GList<%s> is an unsupported type' % el_type)
        elif is_object(arg):
            macro = 'lasso_assign_gobject'
        elif is_hashtable(arg) or is_boolean(arg) or is_int(arg, self.binding_data):
            macro = 'lasso_assign_simple' # FIXME
        else:
            raise Exception('%s is an unsupported type' % arg)
        return '%s(%s, %s);' % (macro, to, fr)

    def generate_xs_functions(self):
        for func in self.binding_data.functions:
            # skip constructors
            if func.name.endswith('new') or '_new_' in func.name:
                continue
            self.generate_xs_function(func)
        for struct in self.binding_data.structs:
            name = struct.name[5:]
            prefix = 'lasso_' + format_as_underscored(name) + '_'
            self.xs.pn('\nMODULE = Lasso\tPACKAGE = Lasso::%s\tPREFIX = %s\n' % (name, prefix))
            # find the constructors
            for func in self.binding_data.functions:
                if func.name.startswith(prefix+'new'):
                    self.generate_xs_function(func)
            for func in struct.methods:
                self.generate_xs_function(func, prefix = prefix)
            for member in struct.members:
                if arg_type(member) ==  'void*':
                    print 'Skipping %s' % member
                    continue
                try:
                    self.generate_xs_getter_setter(struct, member)
                except:
                    print 'failed', struct, member
                    raise

    def generate_wrapper(self):
        pass

    def generate_member_wrapper(self, c):
        pass

    def return_value(self, vtype, options):
        pass

    def element_type2real_type(self, type):
        if is_cstring(type):
            if is_const(type):
                return 'const char*'
            else:
                return 'char*'
        else:
            return type + '*'
