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
const gchar *\tT_PV
gchar *\tT_PV
gboolean\tT_IV
const LassoProvider *\tT_GOBJECT_WRAPPER
xmlNode*\tT_XMLNODE
GList_string\tT_GLIST_STRING
GList_xmlnode\tT_GLIST_XMLNODE
GList_gobject\tT_GLIST_GOBJECT
const GList*\tT_GLIST_STRING
GHashTable*\tT_PTRREF

''')
        # Map integer types
        for int in [ 'int', 'gint', 'long', 'glong'] + self.binding_data.enums:
            self.typemap.pn('%-30s T_IV' % int)

        # Map object types
        for clss in self.binding_data.structs:
            self.typemap.pn('%-30s T_GOBJECT_WRAPPER' % (clss.name + '*'))
            self.typemap.pn('const %-30s T_GOBJECT_WRAPPER' % (clss.name + '*'))

        # Create INPUT & OUTPUT maps
        self.typemap.p(self.file_content('typemap.in'))
        self.typemap.p(self.file_content('typemap.out'))

    def generate_pm_header(self):
        # Lasso.pm
        self.pm.p(package_top)

        for struct in self.binding_data.structs:
            if struct.name != 'LassoNode':
                self.pm.pn('package Lasso::%s;' % struct.name[5:])
                self.pm.pn('our @ISA = qw(%s);' % struct.parent[5:])
                self.pm.pn()

    def generate_xs_header(self):
        '''Generate header of XS file'''
        self.xs.pn('''
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <stdio.h>

#include "gobject_handling.c"
#include "glist_handling.c"

#define lasso_assign_simple(a,b) a = b;

typedef GList* GList_string;
typedef GList* GList_gobject;
typedef GList* GList_xmlnode;

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
    stash = gv_stashpv("Lasso", 1);''')
        self.xs.indent()
        for constant in self.binding_data.constants:
            type, name = constant
            perl_name = name[6:]
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

    def generate_xs_function(self, func):
        name = func.name
        if 'get_nameIden' in name:
            return
        self.xs.pn()
        self.xs.pn(func.return_type or 'void')
        self.xs.p(name + '(')
        arg_list = []
        for arg in func.args:
            if not is_glist(arg):
                arg_list.append('%s %s' % (arg_type(arg), arg_name(arg)))
            elif is_glist(arg):
                arg_list.append('%s %s' % (self.glist_type(arg), arg_name(arg)))
        self.xs.p(','.join(arg_list))
        self.xs.pn(')')
        need_prototype = False
        for x in func.args:
            if is_glist(x):
                need_prototype = True
        if need_prototype:
            self.xs.p('PROTOTYPE: ')
            optional = False
            proto = []
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
            self.xs.pn('''   CLEANUP:
         g_object_unref(RETVAL);''')
        elif func.return_type and is_object(func.return_type) and not is_int(func.return_type, self.binding_data) and func.return_owner:
            self.xs.pn('''   CLEANUP:
         g_object_unref(RETVAL);''')

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
                data = (%(el_type)s) %(convert)s;
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
                'el_type': self.starify(element_type(member)),
                'push': self.push_macro(member),
                'convert': self.convert_function('ST(i)', member),
                'release': self.release_list('obj', member),
                })
        elif is_hashtable(member):
            print >>sys.stderr, 'W: skipping %(cls)s.%(name)s, GHashtable fields are not supported for the momement' % { 'cls': struct.name, 'name': arg_name(member) }

    def starify(self, str):
        if '*' in str:
            return str
        else:
            return str + '*'

    def glist_type(self, member):
        return self.element_type_lookup(member, { 'string': 'GList_string', 'xml_node': 'GList_xmlnode', 'gobject': 'GList_gobject'})

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
        return '%s(%s->%s);' % (macro, what, arg_name(member))

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
                self.generate_xs_function(func)
            for member in struct.members:
                if arg_type(member) ==  'void*':
                    print 'Skipping %s' % member
                    continue
                self.generate_xs_getter_setter(struct, member)

    def generate_wrapper(self):
        pass

    def generate_member_wrapper(self, c):
        pass

    def return_value(self, vtype, options):
        pass

