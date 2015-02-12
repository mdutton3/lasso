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
from six import print_, string_types
import sys
import re
import textwrap

from utils import *

lasso_package_name = 'com.entrouvert.lasso'
lasso_java_path = 'com/entrouvert/lasso/'

debug = 0

def with_return_owner(d):
    c = d.copy()
    c['return_owner'] = 1
    return c

def generate_arg_list(self,args):
    def arg_to_decl(arg):
        return self.java_arg_type(arg) + ' ' + format_as_camelcase(arg_name(arg))
    return ', '.join([ arg_to_decl(x) for x in args if not is_out(x)])

def generate_arg_list2(args):
    def arg_to_decl(arg):
        if is_out(arg):
            return 'output'
        return format_as_camelcase(arg_name(arg))
    return ', '.join([ arg_to_decl(x) for x in args ])

def generate_arg_list3(self, args):
    def arg_to_decl(arg):
        if is_out(arg):
            return 'Object[] output'
        r = self.java_arg_type(arg) + ' ' + format_as_camelcase(arg_name(arg))
        return r
    return ', '.join([ arg_to_decl(x) for x in args])

def convert_class_name(lasso_name):
    return lasso_name[5:]

def mangle_name(name):
    s = name
    s = s.replace('_', '_1')
    s = s.replace(';', '_2')
    s = s.replace('[', '_3')
    return s

def jni_glist_elem_type(type):
    if is_cstring(type):
        return 'jstring'
    elif is_xml_node(type):
        return 'jstring'
    elif is_object(type):
        return 'jobject'
    else:
        return Exception('No jni_glist_elem_type for %s' % (type,))

def jni_hashtable_elem_type(type):
    if is_object(type):
        return 'jobject'
    else:
        return 'jstring'

def JNI_elem_type(type):
    if is_cstring(type):
        return 'String'
    elif is_xml_node(type):
        return 'String'
    elif is_object(type):
        return convert_class_name(type)
    else:
        return 'Object'

def wrapper_name(name):
    return 'Java_com_entrouvert_lasso_LassoJNI_' + mangle_name(name)

def error_to_exception(error_name):
    if 'LASSO_ERROR' in error_name:
        name, = re.match('LASSO_ERROR(_.*)', error_name).groups()
        super = 'Lasso'
    else:
        super, name = re.match('LASSO(_.*)_ERROR(_.*)', error_name).groups()
    super = format_as_camelcase(super.lower())
    name = format_as_camelcase(name.lower())
    return (super+name+'Exception',super+'Exception')

def wrapper_decl(name, jnitype):
    jniname = wrapper_name(name)
    return 'JNIEXPORT %s JNICALL %s(JNIEnv *env, jclass clss' % (jnitype,jniname)

def is_collection(type):
    return is_glist(type) or is_hashtable(type)

class Binding:
    def __init__(self, binding_data):
        self.binding_data = binding_data
        self.src_dir = os.path.dirname(__file__)

    def print_list_of_files(self):
        l = ['GObject.java','LassoConstants.java','LassoJNI.java','LassoException.java', 'LassoUndefinedException.java', 'LassoUnimplementedException.java']
        for c in self.binding_data.structs:
            class_name = convert_class_name(c.name)
            l.append(class_name + '.java')
        for c in self.binding_data.constants:
            type, orig = c
            if 'LASSO_ERROR_' in orig or '_ERROR_' not in orig:
                continue
            name, super = error_to_exception(orig)
            l.append(name + '.java')
            if not super + '.java' in l:
                l.append(super + '.java')
        l = [ lasso_java_path + p for p in l]
        for p in l:
            print_(p, end=" ")
        print_()
        print_()


    def is_gobject_type(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*',
                'const GList*','GList*', 'GHashTable*',
                'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

    def generate(self):
        if not os.path.exists(lasso_java_path):
            os.makedirs(lasso_java_path)
        self.generate_Constants()
        self.generate_JNI()
        self.generate_wrapper()
        self.generate_exception_classes()
        self.generate_lasso_classes()


# LassoConstants
    def generate_Constants(self):
        fd = open(lasso_java_path + 'LassoConstants.java', 'w')
        self.generate_Constants_header(fd)
        self.generate_Constants_constants(fd)
        self.generate_Constants_footer(fd)
        fd.close()

    def generate_Constants_header(self, fd):
        print_('''\
/* this file has been generated automatically; do not edit */

package %s;

public abstract interface LassoConstants {
''' % lasso_package_name, file=fd)

    def generate_Constants_constants(self, fd):
        print_('/* Constants (both enums and defines) */', file=fd)
        # Declaration
        for c in self.binding_data.constants:
            print_('static final ', file=fd, end=" ")
            if c[0] == 'i':
               print_('int ', file=fd, end=" ")
            elif c[0] == 's':
               print_('String ', file=fd, end=" ")
            elif c[0] == 'b':
               print_('boolean ', file=fd, end=" ")
            print_('%s = LassoJNI.%s_get();' % (c[1][6:], c[1]), file=fd)

    def generate_Constants_footer(self, fd):
        print_('}', file=fd)


# LassoJNI
    def generate_JNI(self):
        fd = open(lasso_java_path + 'LassoJNI.java','w')
        self.generate_JNI_header(fd)
        self.generate_JNI_constants(fd)
        for m in self.binding_data.functions:
                self.generate_JNI_functions(m ,fd)
        for c in self.binding_data.structs:
            self.generate_JNI_member(c, fd)
            for m in c.methods:
                self.generate_JNI_functions(m, fd)
        self.generate_JNI_footer(fd)
        fd.close();

    def generate_JNI_header(self, fd):
        print_('''\
/* this file has been generated automatically; do not edit */

package %s;

public final class LassoJNI {
protected static native void init2();
protected static native void destroy(long cptr);
''' % lasso_package_name, file=fd)
    def generate_JNI_constants(self, fd):
        print_('/* Constants getters */', file=fd)
        for c in self.binding_data.constants:
            print_('public static native ', file=fd, end=" ")
            if c[0] == 'i':
                print_('int ', file=fd, end=" ")
            elif c[0] == 's':
                print_('String ', file=fd, end=" ")
            elif c[0] == 'b':
                print_('boolean ', file=fd, end=" ")
            print_('%s_get();' % c[1], file=fd)

    def java_arg_type(self, vtype):
        if is_boolean(vtype):
            return 'boolean'
        elif is_int(vtype, self.binding_data):
            return 'int'
        elif is_cstring(vtype):
            return 'String'
        elif is_collection(vtype):
            return 'Object[]'
        elif is_xml_node(vtype):
            return 'String'
        elif is_object(vtype):
            return convert_class_name(unpointerize(unconstify(vtype)))
        else:
            raise Exception('java_arg_type failed for %s' % vtype)

    def JNI_return_type(self, vtype):
        if vtype:
            m = re.match(r'(?:const\s*)?(.*)',vtype)
            vtype = m.group(1)
        if vtype == 'gboolean':
            return 'boolean'
        elif is_int(vtype, self.binding_data):
            return 'int'
        elif vtype in ('guchar*', 'char*', 'gchar*'):
            return 'String'
        elif vtype in ('const GList*','GList*','GHashTable*'):
            return 'Object[]'
        elif vtype == 'xmlNode*':
            return 'String'
        elif isinstance(vtype,string_types) and vtype.startswith('Lasso'):
            if vtype.endswith('*'):
                vtype = vtype[:-1]
            return convert_class_name(vtype)
        else:
            return 'void'

    def JNI_member_type(self,member):
        if is_glist(member):
            return self.java_arg_type(element_type(member))
        elif is_hashtable(member):
            return self.java_arg_type(element_type(member) or 'char*')
        else:
            return self.java_arg_type(member)

    def JNI_function_name(self, m):
        if m.rename:
            return m.rename
        else:
            return m.name[6:]

    def generate_JNI_functions(self, m, fd):
        if m.name.endswith('_new'):
            jtype = 'long'
        else:
            jtype = self.JNI_return_type(m.return_type)
        name = self.JNI_function_name(m)
        print_('   public static native %s %s(%s);' % (jtype,name, generate_arg_list3(self,m.args)), file=fd)

    def JNI_member_function_prefix(self,c,m):
        klassname = c.name[5:]
        mname = old_format_as_camelcase(m[1])
        return '%s_%s' % (klassname,mname)

    def generate_JNI_member(self, c, fd):
        for m in c.members:
            prefix = self.JNI_member_function_prefix(c,m)
            mname = format_as_camelcase(m[1])
            mtype = m[0]

            jtype = self.JNI_member_type(m)
            if mtype == 'GList*'or mtype == 'const GList*':
                name = '%s_get' % prefix
                print_('   public static native %s[] %s(GObject obj);' % (jtype,name), file=fd)
                name = '%s_set' % prefix
                print_('   public static native void %s(GObject obj, %s[] value);' % (name,jtype), file=fd)
                name = '%s_add' % prefix
                print_('   public static native void %s(GObject obj, %s value);' % (name,jtype), file=fd)
                if not m[2].get('element-type') in ('xmlNode*',):
                    name = '%s_remove' % prefix
                    print_('   public static native void %s(GObject obj, %s value);' % (name,jtype), file=fd)
            elif mtype == 'GHashTable*':
                name = '%s_get' % prefix
                print_('   public static native %s[] %s(GObject obj);' % (jtype,name), file=fd)
                name = '%s_set' % prefix
                print_('   public static native void %s(GObject obj, %s[] value);' % (name,jtype), file=fd)
            else:
                name = '%s_get' % prefix
                print_('   public static native %s %s(GObject obj);' % (jtype,name), file=fd)
                name = '%s_set' % prefix
                print_('   public static native void %s(GObject obj, %s value);' % (name,jtype), file=fd)

    def generate_JNI_footer(self, fd):
        print_('''
    static {
        System.loadLibrary("jnilasso");
        init();
        init2();
    }
''', file=fd)
        print_('}', file=fd)


# Wrappers
    def generate_wrapper(self):
        fd = open('com_entrouvert_lasso_LassoJNI.c', 'w')
        self.generate_wrapper_header(fd)
        self.generate_wrapper_constants(fd)

        print_('/* Declaration of standalone functions */', file=fd)
        for m in self.binding_data.functions:
            self.generate_wrapper_function(m, fd)
        print_('/* End of declaration of standalone functions */', file=fd)
        print_('/* Declaration of getter/setter methods */', file=fd)
        for c in self.binding_data.structs:
            self.generate_wrapper_getter_setter(c, fd)
        print_('/* End of declaration of getter/setter methods */', file=fd)
        for c in self.binding_data.structs:
            for m in c.methods:
                self.generate_wrapper_function(m, fd)
        print_(open(os.path.join(self.src_dir,'wrapper_bottom.c')).read(), file=fd)
        fd.close()

    def generate_wrapper_header(self, fd):
        print_(open(os.path.join(self.src_dir,'wrapper_top.c')).read(), file=fd)
        print_('', file=fd)
        for h in self.binding_data.headers:
            print_('#include <%s>' % h, file=fd)


    def generate_wrapper_constants(self, fd):
        print_('/* Declaration of constants */', file=fd)
        for c in self.binding_data.constants:
            s = c[1]+'_get'
            if c[0] == 'i':
                print_(wrapper_decl(s,'jint'), file=fd)
                print_(') {', file=fd)
                print_('   return %s;' % c[1], file=fd)
                print_('}', file=fd)
            elif c[0] == 's':
                print_(wrapper_decl(s,'jstring'), file=fd)
                print_(') {', file=fd)
                print_('   return (*env)->NewStringUTF(env, (char*) %s);' % c[1], file=fd)
                print_('}', file=fd)
            elif c[0] == 'b':
                print_(wrapper_decl(s,'jboolean'), file=fd)
                print_(') {', file=fd)
                print_('#ifdef %s' % c[1], file=fd)
                print_('   return 1;', file=fd)
                print_('#else', file=fd)
                print_('   return 0;', file=fd)
                print_('#endif', file=fd)
                print_('}', file=fd)
        print_('/* End of declaration of constants */', file=fd)

    def jni_return_type(self, type):
        if type is None:
            return 'void'
        elif is_boolean(type):
            return 'jboolean'
        elif is_int(type, self.binding_data):
            return 'jint'
        elif is_cstring(type):
            return 'jstring'
        elif is_glist(type) or is_hashtable(type):
            return 'jobjectArray'
        elif is_xml_node(type):
            return 'jstring'
        elif is_object(type):
            return 'jobject'
        else:
            raise Exception('No jni_return_type for %s' % type)

    def c_to_java_value(self, left, right, type):
        if is_boolean(type):
            return '%s = (jboolean)%s' % (left,right)
        elif is_int(type, self.binding_data):
            return '%s = (jint)%s' % (left, right)
        elif is_cstring(type):
            return 'string_to_jstring(env, %s, &%s)' % (right, left)
        elif is_glist(type):
            el_type = element_type(type)
            if is_cstring(el_type):
                return 'get_list_of_strings(env, %s, &%s)' % (right, left)
            elif is_xml_node(el_type):
                return 'get_list_of_xml_nodes(env, %s, &%s)' % (right, left)
            elif is_object(el_type):
                return 'get_list_of_objects(env, %s, &%s)' % (right, left)
            else:
                raise Exception('c_to_java_value failed, %s' % ((left, right, type),))
        elif is_hashtable(type):
            el_type = element_type(type)
            if is_object(el_type):
                return 'get_hash_of_objects(env, %s, &%s)' % (right, left)
            else:
                return 'get_hash_of_strings(env, %s, &%s)' % (right, left)
        elif is_xml_node(type):
                return 'xml_node_to_jstring(env, %s, &%s)' % (right, left)
        elif is_object(type):
            if is_transfer_full(type):
                return 'gobject_to_jobject(env, (GObject*)%s, &%s);' % (right, left)
            else:
                return 'gobject_to_jobject_and_ref(env, (GObject*)%s, &%s);' % (right, left)
        else:
            raise Exception('c_to_java_value failed, %s' % ((left, right, type),))

    def java_to_c_value(self, left, right, type, full = False):
        if is_boolean(type) or is_int(type, self.binding_data):
            return '%s = (%s)%s;' % (left,arg_type(type),right)
        elif is_cstring(type):
            return 'jstring_to_string(env, %s, (char**)&%s);' % (right,left)
        elif is_glist(type):
            el_type = element_type(type)
            if is_cstring(el_type):
                return 'set_list_of_strings(env, &%s,%s);' % (left,right)
            elif is_xml_node(el_type):
                return 'set_list_of_xml_nodes(env, &%s, %s);' % (left, right)
            elif is_object(el_type):
                return 'set_list_of_objects(env, &%s, %s);' % (left, right)
            else:
                raise Exception('java_to_c_value failed: %s' % ((left, right, type),))
        elif is_hashtable(type):
            el_type = element_type(type)
            if is_object(el_type):
                return 'set_hash_of_objects(env, %s, %s);' % (left,right)
            else:
                return 'set_hash_of_strings(env, %s, %s);' % (left,right)
        elif is_xml_node(type):
            return 'jstring_to_xml_node(env, %s, &%s);' % (right, left)
        elif is_object(type):
            if is_transfer_full(type) or full:
                return 'jobject_to_gobject(env, %s, (GObject**)&%s);' % (right, left)
            else:
                return 'jobject_to_gobject_noref(env, %s, (GObject**)&%s);' % (right, left)
        else:
            raise Exception('java_to_c_value failed: %s'  % ((left, right, type),))


    def generate_wrapper_function(self, m, fd):
        print_('/* Wrapper function for ', file=fd, end=" ")
        if m.return_type:
            print_(m.return_type, file=fd, end=" ")
        else:
            print_('void', file=fd, end=" ")
        print_('%s(' % m.name, file=fd, end=" ")
        for arg in m.args:
            print_('%s %s %s,' % (arg[0],arg[1],arg[2]), file=fd, end=" ")
        print_(') */', file=fd)
        if m.rename:
            name = m.rename
        else:
            name = m.name[6:]
#        self.wrapper_list.append(name)
#        print_('''static PyObject*, file=fd)
#%s(PyObject *self, PyObject *args)
#{''' % name
        if m.name.endswith('_new'):
            jtype = 'jlong'
        else:
            jtype = self.jni_return_type(m.return_type)
        print_(wrapper_decl(name, jtype), file=fd)
        parse_tuple_format = []
        parse_tuple_args = []
        idx = 0
        # Declare java args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            print_(',%s jarg%s' % (self.jni_return_type(arg_type.replace('const ','')),idx), file=fd, end=" ")
        print_(')', file=fd)
        print_('  {', file=fd)
        idx = 0
        if m.return_type:
            print_('    %s ret;' % jtype, file=fd)
        # Declare C args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            if is_pointer(arg):
                print_('    %s %s = NULL;' % (arg_type.replace('const ',''),arg_name), file=fd)
            else:
                print_('    %s %s;' % (arg_type.replace('const ',''),arg_name), file=fd)
        # Declare return vars
        if m.return_type:
            print_('    %s return_value;' % m.return_type, file=fd)
        idx = 0
        # Convert args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            print_('    %s' % self.java_to_c_value(arg_name, 'jarg%s' % idx, arg), file=fd)
        if debug:
            print_('    printf("%s' % name, file=fd, end=" ")
            arglist = ''
            for  arg in m.args:
                arg_type, arg_name, arg_options = arg
                arglist = arglist + ', %s' % arg_name
                if is_int(arg_type, self.binding_data):
                    print_('%i', file=fd, end=" ")
                elif is_cstring(arg_type):
                    print_('%s', file=fd, end=" ")
                else:
                    print_('%p', file=fd, end=" ")
            print_('\\n"%s);' % arglist, file=fd)
        # Call function
        print_('   ', file=fd, end=" ")
        if m.return_type:
            print_('return_value = ', file=fd, end=" ")
            if 'new' in m.name:
                print_('(%s)' % m.return_type, file=fd, end=" ")
        def arg2ref(x):
            if is_const(x):
                return '(%s) %s' % (x[0],x[1]) 
            else:
                return x[1]
        print_('%s(%s);' % (m.name, ', '.join([arg2ref(x) for x in m.args])), file=fd)
        # Free const char * args
        idx=0
        for arg in m.args:
            idx=idx+1
            arg_type, arg_name, arg_options = arg
            if is_cstring(arg_type):
                print_('    if (%s)' % arg_name, file=fd)
                print_('        g_free(%s);' % arg_name, file=fd)
            elif arg_type == 'GList*' or arg_type == 'const GList*':
                if is_cstring(element_type(arg)):
                    print_('    free_glist(&%s, (GFunc)free);' % arg_name, file=fd)
                elif is_object(element_type(arg)):
                    print_('    free_glist(&%s, (GFunc)g_object_unref);' % arg_name, file=fd)
                else:
                    raise Exception('Freeing args of type list of \'%s\' not supported.' % arg_options.get('element-type'))

        # Return
        if m.return_type:
            if m.name.endswith('_new'):
                print_('    ret = (jlong)(ptrdiff_t) return_value;', file=fd)
            else:
                options = {}
                if m.return_owner:
                    options = with_return_owner({})
                print_('    %s;' % self.c_to_java_value('ret','return_value', m.return_arg), file=fd)
                if m.return_owner:
                    if m.return_type == 'GList*' or m.return_type == 'const GList*':
                        print_('    free_glist(&return_value, NULL);', file=fd)
                    elif is_cstring(m.return_type) and not is_const(m.return_arg):
                        print_('    if (return_value)', file=fd)
                        print_('        g_free(return_value);', file=fd)
            print_('    return ret;', file=fd)
        print_('  }', file=fd)

    def generate_wrapper_getter(self, c, m, fd):
        type = arg_type(m)
        name = arg_name(m)
        klass = c.name
        prefix = self.JNI_member_function_prefix(c,m)
        return_type = self.jni_return_type(m)
        signature = wrapper_decl("%s_get" % prefix, return_type)
        field = 'gobj->%s' % name
        d = locals()
        print_('''
/* Getter for %(type)s %(klass)s.%(name)s */
%(signature)s, jobject jobj)  {
    %(klass)s *gobj = NULL;
    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);''' % d, file=fd)
        if debug:
            print_('    printf("%(prefix)s_get %%p %%p\\n", gobj, %(field)s);' % d, file=fd)
        print_('    %(return_type)s ret = 0;' % d, file=fd)
        print_('    if (gobj) {', file=fd)
        print_('         %s;' % self.c_to_java_value ('ret', d['field'], m), file=fd)
        print_('''    } else {
                 throw_by_name(env, "java/lang/NullPointerException", "no gobject correspond to the given object");
            }
            return ret;
        }
''', file=fd)

    def generate_wrapper_setter(self, c, m, fd):
        type = arg_type(m)
        name = arg_name(m)
        klass = c.name
        prefix = self.JNI_member_function_prefix(c,m)
        return_type = self.jni_return_type(m)
        signature = wrapper_decl("%s_set" % prefix, 'void')
        field = 'gobj->%s' % name
        d = locals()

        print_('/* Setter for %(type)s %(klass)s.%(name)s */' % d, file=fd)
        print_('%(signature)s, jobject jobj, %(return_type)s value)\n  {' % d, file=fd)
        print_('    %(klass)s *gobj = NULL;' % d, file=fd)
        if debug:
            print_('    printf("%(prefix)s_set %%p %%p\\n", gobj, value);' % d, file=fd)
        print_('    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);', file=fd)
        print_('    if (!gobj) {', file=fd)
        print_('        throw_by_name(env, "java/lang/NullPointerException", "no gobject correspond to the given object");', file=fd)
        print_('    }', file=fd)
        print_('    %s' % self.java_to_c_value(d['field'], 'value', m, full = True), file=fd)
        print_('}', file=fd)

    def generate_wrapper_adder(self, c, m, fd):
        type = arg_type(m)
        name = arg_name(m)
        el_type = element_type(m)
        jni_el_type = jni_glist_elem_type(el_type)
        klass = c.name
        prefix = self.JNI_member_function_prefix(c,m)
        return_type = self.jni_return_type(m)
        signature = wrapper_decl("%s_add" % prefix, 'void')
        field = 'gobj->%s' % name
        d = locals()

        print_('/* Adder for %(type)s<%(el_type)s> %(klass)s.%(name)s */' % d, file=fd)
        print_('%(signature)s, jobject jobj, %(jni_el_type)s value)\n  {' % d, file=fd)
        print_('    %(klass)s *gobj = NULL;' % d, file=fd)
        print_('    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);', file=fd)
        if is_cstring(el_type):
            print_('    add_to_list_of_strings(env, &%(field)s, value);' % d, file=fd)
        elif is_xml_node(el_type):
            print_('    add_to_list_of_xml_nodes(env, &%(field)s, value);' % d, file=fd)
        elif is_object(el_type):
            print_('    add_to_list_of_objects(env, &%(field)s, value);' % d, file=fd)
        else:
            raise Exception('generate_wrapper_adder failed for %s.%s' % (c,m))
        print_('}', file=fd)

    def generate_wrapper_remover(self, c, m, fd):
        type = arg_type(m)
        name = arg_name(m)
        klass = c.name
        el_type = element_type(m)
        jni_el_type = jni_glist_elem_type(el_type)
        prefix = self.JNI_member_function_prefix(c,m)
        return_type = self.jni_return_type(m)
        signature = wrapper_decl("%s_remove" % prefix, 'void')
        field = 'gobj->%s' % name
        d = locals()

        if is_xml_node(el_type):
            print_('W: remove for list of xml node not supported: %s' % (m,), file=sys.stderr)
            return
        print_('/* Remover for %(type)s<%(el_type)s> %(klass)s.%(name)s */' % d, file=fd)
        print_('%(signature)s, jobject jobj, %(jni_el_type)s value)\n  {' % d, file=fd)
        print_('    %(klass)s *gobj = NULL;' % d, file=fd)
        print_('    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);', file=fd)
        if is_cstring(el_type):
            print_('    remove_from_list_of_strings(env, &%(field)s,value);' % d, file=fd)
        elif is_object(el_type):
            print_('    remove_from_list_of_objects(env, &%(field)s,value);' % d, file=fd)
        else:
            raise Exception('remove_from_list unsupported for %s.%s' % (c,m,))
        print_('}', file=fd)
        print_('', file=fd)

    def generate_wrapper_getter_setter(self, c, fd):
        klassname = c.name
        for m in c.members:
            # getter
            self.generate_wrapper_getter(c, m, fd)
            self.generate_wrapper_setter(c, m, fd)
            mtype = m[0]
            prefix = self.JNI_member_function_prefix(c,m)
            jtype = self.jni_return_type(mtype)
            # add/remove
            if is_glist(mtype):
                self.generate_wrapper_adder(c, m, fd)
                self.generate_wrapper_remover(c, m, fd)

    def generate_exception_switch_case(self, fd, name, orig):
        print_('        if (errorCode == LassoConstants.%s) {' % orig[6:], file=fd)
        print_('            throw new %s(errorCode);' % name, file=fd)
        print_('        }', file=fd)

    def generate_exception_classes(self):
        efd = open(lasso_java_path + 'LassoException.java', 'w')
        print_(open(os.path.join(self.src_dir,'LassoException_top.java')).read(), file=efd)
        # Generate the function to get class name by error code
        supers = []
        for c in self.binding_data.constants:
            type, orig = c
            if 'LASSO_ERROR_' in orig or '_ERROR_' not in orig:
                continue
            name, super = error_to_exception(orig)
            self.generate_exception_switch_case(efd, name, orig)
            if super not in supers:
                supers.append(super)
            self.generate_exception_class(name,super,0,orig)
        for s in supers:
            self.generate_exception_class(s,'LassoException',1,'')
        # Special errors, UNIMPLEMENTED and UNDEFINED
        for c in self.binding_data.constants:
            type, orig = c
            if 'LASSO_ERROR_' not in orig:
                continue
            name, = re.match('LASSO_ERROR(.*)',orig).groups()
            name = name.lower()
            name = format_underscore_as_camelcase(name)
            name = 'Lasso%sException' % name
            self.generate_exception_class(name, 'LassoException', 0, orig)
            self.generate_exception_switch_case(efd, name, orig)
        print_('        throw new LassoException(errorCode, "Uknown lasso error code, maybe a bug in the binding, report it!");', file=efd)
        print_('    }', file=efd)
        print_('}', file=efd)
        efd.close()


    def generate_exception_class(self, name, super,abstract,orig):
            fd = open(lasso_java_path + '%s.java' % name, 'w')
            print_('package %s;' % lasso_package_name, file=fd)
            print_('', file=fd)
            if abstract:
                print_('abstract ', file=fd, end=" ")
            print_('public class %s extends %s {' % (name,super), file=fd)
            print_('    private static final long serialVersionUID = 6170037639785281128L;', file=fd)
            if not abstract:
                print_('    public %s() {' % name, file=fd)
                print_('       super(LassoConstants.%s);' % orig[6:], file=fd)
                print_('    }', file=fd)
            print_('    protected %s(int errorCode) {' % name, file=fd)
            print_('        super(errorCode);', file=fd)
            print_('    }', file=fd)
            print_('}', file=fd)
            fd.close()

    # Generate classes for Lasso Objects
    def generate_lasso_classes(self):
        def method_name(m,class_name):
            prefix = len(class_name)
            if m.rename:
                return m.rename
            else:
                name = format_as_camelcase(m.name[6:])
                name = name[prefix:]
                return name[0].lower() + name[1:]
        for c in self.binding_data.structs:
            class_name = convert_class_name(c.name)
            parent_name = c.parent
            if parent_name != 'GObject':
                parent_name = convert_class_name(parent_name)
            path = lasso_java_path + '%s.java' % class_name
            fd = open(path,'w')
            print_('package %s;' % lasso_package_name, file=fd)
            do_import_util = 0
            for m in c.members:
                if m[0] in ('const GList*','GList*','GHashTable*'):
                    do_import_util = 1
            for m in c.methods:
                if m.return_type in ('const GList*','GList*','GHashTable*'):
                    do_import_util = 1
            if do_import_util:
                print_('import java.util.*;', file=fd)
            print_('', file=fd)
            print_('public class %s extends %s {' % (class_name,parent_name), file=fd)
            # Constructeur private
            print_('    /* Constructors */', file=fd)
            print_('    protected %s(long cptr) {' % class_name, file=fd)
            print_('        super(cptr);', file=fd)
            print_('    }', file=fd)
            # Constructeur de base
            def cprefix(name):
                i = name.find('_new')
                if i == -1:
                    return name
                else:
                    return name[:i].replace('_','').lower()
            cons = [ x for x in self.binding_data.functions if cprefix(x.name) == c.name.lower() and x.name.endswith('_new') ]
            for m in cons:
                print_('    public %s(%s) {' % (class_name, generate_arg_list(self,m.args)), file=fd)
                print_('        super(LassoJNI.%s(%s));' % (self.JNI_function_name(m),generate_arg_list2(m.args)), file=fd)
                print_('    }', file=fd)
            # Constructeurs speciaux
            cons = [ x for x in self.binding_data.functions if cprefix(x.name) == c.name.lower() and not x.name.endswith('_new') ]
            for m in cons:
                name = method_name(m,class_name)
                print_('    static public %s %s(%s) {' % (class_name, name, generate_arg_list(self,m.args)), file=fd)
                print_('        return (%s) LassoJNI.%s(%s);' % (class_name, self.JNI_function_name(m),generate_arg_list2(m.args)), file=fd)
                print_('    }', file=fd)
            print_('    /* Setters and getters */', file=fd)
            for m in c.members:
                type, name, options = m
                prefix = self.JNI_member_function_prefix(c,m)
                jname = format_as_camelcase(name)
                jname = jname[0].capitalize() + jname[1:]
                old_jname = old_format_as_camelcase('_' + name)
                jtype = self.JNI_member_type(m)
                if type == 'GList*' or type == 'const GList*':
                    print_('    public void set%s(List list) {' % jname, file=fd)
                    print_('        %s[] arr = null;' % jtype, file=fd)
                    print_('        if (list != null) {', file=fd)
                    print_('            arr = new %s[list.size()];' % jtype, file=fd)
                    print_('            listToArray(list, arr);', file=fd)
                    print_('        }', file=fd)
                    print_('        LassoJNI.%s_set(this, arr);' % prefix, file=fd)
                    print_('    }', file=fd)
                    print_('    public List get%s() {' % jname, file=fd)
                    print_('        %s[] arr = LassoJNI.%s_get(this);' % (jtype,prefix), file=fd)
                    print_('        if (arr != null)', file=fd)
                    print_('            return Arrays.asList(arr);', file=fd)
                    print_('        else', file=fd)
                    print_('            return new ArrayList(0);', file=fd)
                    print_('    }', file=fd)
                    print_('    public void addTo%s(%s value) {' % (jname,jtype), file=fd)
                    print_('        LassoJNI.%s_add(this, value);' % prefix, file=fd)
                    print_('    }', file=fd)
                    if m[2].get('element-type') not in ('xmlNode*',):
                        print_('    public void removeFrom%s(%s value) {' % (jname,jtype), file=fd)
                        print_('        LassoJNI.%s_remove(this, value);' % prefix, file=fd)
                        print_('    }', file=fd)
                    if old_jname != jname:
                        print_('    public void set%s(List list) {' % old_jname, file=fd)
                        print_('        this.set%s(list);' % jname, file=fd)
                        print_('    }', file=fd)
                        print_('    public List get%s() {' % old_jname, file=fd)
                        print_('        return this.get%s();' % jname, file=fd)
                        print_('    }', file=fd)
                        print_('    public void addTo%s(%s value) {' % (old_jname,jtype), file=fd)
                        print_('        this.addTo%s(value);' % jname, file=fd)
                        print_('    }', file=fd)
                        if m[2].get('element-type') not in ('xmlNode*',):
                            print_('    public void removeFrom%s(%s value) {' % (old_jname,jtype), file=fd)
                            print_('        this.removeFrom%s(value);' % jname, file=fd)
                            print_('    }', file=fd)
                elif type == 'GHashTable*':
                    print_('    public void set%s(Map map) {' % jname, file=fd)
                    print_('        %s[] arr = null;' % jtype, file=fd)
                    print_('        if (map != null) {', file=fd)
                    print_('            arr = new %s[map.size()*2];' % jtype, file=fd)
                    print_('            mapToArray(map,arr);', file=fd)
                    print_('        }', file=fd)
                    print_('        LassoJNI.%s_set(this, arr);' % prefix, file=fd)
                    print_('    }', file=fd)
                    print_('    public Map get%s() {' % jname, file=fd)
                    print_('        return arrayToMap(LassoJNI.%s_get(this));' % prefix, file=fd)
                    print_('    }', file=fd)
                else:
                    print_('    public void set%s(%s value) {' % (jname,jtype), file=fd)
                    print_('        LassoJNI.%s_set(this, value);' % prefix, file=fd)
                    print_('    }', file=fd)
                    print_('    public %s get%s() {' % (jtype,jname), file=fd)
                    print_('        return LassoJNI.%s_get(this);' % prefix, file=fd)
                    print_('    }', file=fd)
                    if old_jname != jname:
                        print_('    public void set%s(%s value) {' % (old_jname,jtype), file=fd)
                        print_('        this.set%s(value);' % jname, file=fd)
                        print_('    }', file=fd)
                        print_('    public %s get%s() {' % (jtype,old_jname), file=fd)
                        print_('        return this.get%s();' % jname, file=fd)
                        print_('    }', file=fd)
            print_('    /* Methods */', file=fd)
            for m in c.methods:
                return_type = self.JNI_return_type(m.return_type)
                jni_name = self.JNI_function_name(m)
                mname = method_name(m,class_name)
                args = m.args
                doc = m.docstring
                def normalize(str,first='      * '):
                    wrapper = textwrap.TextWrapper()
                    wrapper.initial_indent = first
                    wrapper.subsequent_indent = '      * '
                    str = re.sub(r'\bNULL\b','null', str)
                    str = re.sub(r'#Lasso(\w+)',r'{@@link \1}',str)
                    str = re.sub(r'[^.]*must *be *freed *by[^.]*\.?', '', str)
                    str = re.sub(r'[^.]*internally[^.]*\.?[^.]*freed[^.]*\.?', '', str)

                    str = re.sub(r'[^.]*\bfreed?\b[^.]*\.?', '', str)
                    str = re.sub(r'(a +)?#?GList\*?','an array', str)
                    return wrapper.fill(re.sub(r'@\b(\w+)\b',r'\1',str))
                if doc:
                    first = normalize(doc.description, '    /** ')
                    if first:
                        print_(first, file=fd)
                    else:
                        print_('    /**\n', file=fd)
                    print_('      *', file=fd)
                    for p in doc.parameters:
                        name = p[0]
                        desc = p[1]
                        print_(normalize(desc, '      * @param %s ' % format_as_camelcase(name)), file=fd)
                    if doc.return_value:
                        print_(normalize(doc.return_value, '      * @return '), file=fd)
                    if m.errors:
                        for err in m.errors:
                            err = error_to_exception(err)[0]
                            print_(normalize(err,'      * @throws '), file=fd)
                    print_('    **/', file=fd)
                outarg = None
                for a in args:
                    if is_out(a):
                        # only one output arg supported
                        assert not outarg
                        outarg = a
                if outarg:
                    assert is_int(make_arg(m.return_type), self.binding_data)
                    new_return_type = self.JNI_return_type(var_type(outarg))
                    print_('    public %s %s(%s) {' % (new_return_type, mname, generate_arg_list(self, args[1:])), file=fd)
                    print_('        Object[] output = new Object[1];', file=fd)
                    print_('        LassoException.throwError(LassoJNI.%s(this, %s));' % (jni_name, generate_arg_list2(args[1:])), file=fd)
                    print_('        return (%s)output[0];' % new_return_type, file=fd)
                    print_('    }', file=fd)

                elif m.return_type == 'GList*' or m.return_type == 'const GList*':
                    print_('    public List %s(%s) {' % (mname,generate_arg_list(self,args[1:])), file=fd)
                    arglist = generate_arg_list2(args[1:])
                    if arglist:
                        arglist = ', ' + arglist
                    print_('        Object[] arr = LassoJNI.%s(this%s);' % (jni_name,arglist), file=fd)
                    print_('        if (arr != null)', file=fd)
                    print_('            return Arrays.asList(arr);', file=fd)
                    print_('        else', file=fd)
                    print_('            return null;', file=fd)
                    print_('    }', file=fd)
                else:
                    print_('    public %s %s(%s) {' % (return_type,mname,generate_arg_list(self,args[1:])), file=fd)
                    print_('       ', file=fd, end=" ")
                    if m.return_type:
                        print_('return', file=fd, end=" ")
                    arglist = generate_arg_list2(args[1:])
                    if arglist:
                        arglist = ', ' + arglist
                    if is_rc(m.return_type):
                        print_('LassoException.throwError(', file=fd, end=" ")
                    print_('LassoJNI.%s(this%s)' % (jni_name,arglist), file=fd)
                    if is_rc(m.return_type):
                        print_(');', file=fd)
                    else:
                        print_(';', file=fd)
                    print_('    }', file=fd)
            print_('}', file=fd)
            fd.close()
