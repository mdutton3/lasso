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
            print p,
        print
        print


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
        print >> fd, '''\
/* this file has been generated automatically; do not edit */

package %s;

public abstract interface LassoConstants {
''' % lasso_package_name

    def generate_Constants_constants(self, fd):
        print >> fd, '/* Constants (both enums and defines) */'
        # Declaration
        for c in self.binding_data.constants:
            print >> fd, 'static final ',
            if c[0] == 'i':
               print >> fd, 'int ',
            elif c[0] == 's':
               print >> fd, 'String ',
            elif c[0] == 'b':
               print >> fd, 'boolean ',
            print >> fd, '%s = LassoJNI.%s_get();' % (c[1][6:], c[1])

    def generate_Constants_footer(self, fd):
        print >> fd, '}'


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
        print >> fd, '''\
/* this file has been generated automatically; do not edit */

package %s;

public final class LassoJNI {
protected static native void init2();
protected static native void destroy(long cptr);
''' % lasso_package_name
    def generate_JNI_constants(self, fd):
        print >>fd, '/* Constants getters */'
        for c in self.binding_data.constants:
            print >>fd, 'public static native ',
            if c[0] == 'i':
                print >>fd, 'int ',
            elif c[0] == 's':
                print >>fd, 'String ',
            elif c[0] == 'b':
                print >>fd, 'boolean ',
            print >>fd, '%s_get();' % c[1]

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
        elif isinstance(vtype,basestring) and vtype.startswith('Lasso'):
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
        print >> fd, '   public static native %s %s(%s);' % (jtype,name, generate_arg_list3(self,m.args))

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
                print >> fd, '   public static native %s[] %s(GObject obj);' % (jtype,name)
                name = '%s_set' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s[] value);' % (name,jtype)
                name = '%s_add' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s value);' % (name,jtype)
                if not m[2].get('element-type') in ('xmlNode*',):
                    name = '%s_remove' % prefix
                    print >> fd, '   public static native void %s(GObject obj, %s value);' % (name,jtype)
            elif mtype == 'GHashTable*':
                name = '%s_get' % prefix
                print >> fd, '   public static native %s[] %s(GObject obj);' % (jtype,name)
                name = '%s_set' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s[] value);' % (name,jtype)
            else:
                name = '%s_get' % prefix
                print >> fd, '   public static native %s %s(GObject obj);' % (jtype,name)
                name = '%s_set' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s value);' % (name,jtype)

    def generate_JNI_footer(self, fd):
        print >>fd, '''
    static {
        System.loadLibrary("jnilasso");
        init();
        init2();
    }
'''
        print >>fd, '}'


# Wrappers
    def generate_wrapper(self):
        fd = open('com_entrouvert_lasso_LassoJNI.c', 'w')
        self.generate_wrapper_header(fd)
        self.generate_wrapper_constants(fd)

        print >> fd, '/* Declaration of standalone functions */'
        for m in self.binding_data.functions:
            self.generate_wrapper_function(m, fd)
        print >> fd, '/* End of declaration of standalone functions */'
        print >> fd, '/* Declaration of getter/setter methods */'
        for c in self.binding_data.structs:
            self.generate_wrapper_getter_setter(c, fd)
        print >> fd, '/* End of declaration of getter/setter methods */'
        for c in self.binding_data.structs:
            for m in c.methods:
                self.generate_wrapper_function(m, fd)
        print >> fd, open(os.path.join(self.src_dir,'wrapper_bottom.c')).read()
        fd.close()

    def generate_wrapper_header(self, fd):
        print >> fd, open(os.path.join(self.src_dir,'wrapper_top.c')).read()
        print >> fd, ''
        for h in self.binding_data.headers:
            print >> fd, '#include <%s>' % h


    def generate_wrapper_constants(self, fd):
        print >> fd, '/* Declaration of constants */'
        for c in self.binding_data.constants:
            s = c[1]+'_get'
            if c[0] == 'i':
                print >>fd, wrapper_decl(s,'jint')
                print >>fd, ') {'
                print >>fd, '   return %s;' % c[1]
                print >>fd, '}'
            elif c[0] == 's':
                print >>fd, wrapper_decl(s,'jstring')
                print >>fd, ') {'
                print >>fd, '   return (*env)->NewStringUTF(env, (char*) %s);' % c[1]
                print >>fd, '}'
            elif c[0] == 'b':
                print >>fd, wrapper_decl(s,'jboolean')
                print >>fd, ') {'
                print >>fd, '#ifdef %s' % c[1]
                print >>fd, '   return 1;'
                print >>fd, '#else'
                print >>fd, '   return 0;'
                print >>fd, '#endif'
                print >>fd, '}'
        print >> fd, '/* End of declaration of constants */'

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
        print >> fd, '/* Wrapper function for ',
        if m.return_type:
            print >> fd, m.return_type,
        else:
            print >> fd, 'void',
        print >> fd, '%s(' % m.name,
        for arg in m.args:
            print >> fd, '%s %s %s,' % (arg[0],arg[1],arg[2]),
        print >> fd, ') */'
        if m.rename:
            name = m.rename
        else:
            name = m.name[6:]
#        self.wrapper_list.append(name)
#        print >> fd, '''static PyObject*
#%s(PyObject *self, PyObject *args)
#{''' % name
        if m.name.endswith('_new'):
            jtype = 'jlong'
        else:
            jtype = self.jni_return_type(m.return_type)
        print >>fd, wrapper_decl(name, jtype)
        parse_tuple_format = []
        parse_tuple_args = []
        idx = 0
        # Declare java args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            print >> fd, ',%s jarg%s' % (self.jni_return_type(arg_type.replace('const ','')),idx),
        print >> fd, ')'
        print >> fd, '  {'
        idx = 0
        if m.return_type:
            print >> fd, '    %s ret;' % jtype
        # Declare C args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            if is_pointer(arg):
                print >> fd, '    %s %s = NULL;' % (arg_type.replace('const ',''),arg_name)
            else:
                print >> fd, '    %s %s;' % (arg_type.replace('const ',''),arg_name)
        # Declare return vars
        if m.return_type:
            print >> fd, '    %s return_value;' % m.return_type
        idx = 0
        # Convert args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            print >> fd, '    %s' % self.java_to_c_value(arg_name, 'jarg%s' % idx, arg)
        if debug:
            print >> fd, '    printf("%s' % name,
            arglist = ''
            for  arg in m.args:
                arg_type, arg_name, arg_options = arg
                arglist = arglist + ', %s' % arg_name
                if is_int(arg_type, self.binding_data):
                    print >> fd, '%i',
                elif is_cstring(arg_type):
                    print >> fd, '%s',
                else:
                    print >> fd, '%p',
            print >> fd, '\\n"%s);' % arglist
        # Call function
        print >> fd, '   ',
        if m.return_type:
            print >> fd, 'return_value = ',
            if 'new' in m.name:
                print >>fd, '(%s)' % m.return_type,
        def arg2ref(x):
            if is_const(x):
                return '(%s) %s' % (x[0],x[1]) 
            else:
                return x[1]
        print >> fd, '%s(%s);' % (m.name, ', '.join([arg2ref(x) for x in m.args]))
        # Free const char * args
        idx=0
        for arg in m.args:
            idx=idx+1
            arg_type, arg_name, arg_options = arg
            if is_cstring(arg_type):
                print >> fd, '    if (%s)' % arg_name
                print >> fd, '        g_free(%s);' % arg_name
            elif arg_type == 'GList*' or arg_type == 'const GList*':
                if is_cstring(element_type(arg)):
                    print >> fd, '    free_glist(&%s, (GFunc)free);' % arg_name
                elif is_object(element_type(arg)):
                    print >> fd, '    free_glist(&%s, (GFunc)g_object_unref);' % arg_name
                else:
                    raise Exception('Freeing args of type list of \'%s\' not supported.' % arg_options.get('element-type'))

        # Return
        if m.return_type:
            if m.name.endswith('_new'):
                print >> fd, '    ret = (jlong)(ptrdiff_t) return_value;'
            else:
                options = {}
                if m.return_owner:
                    options = with_return_owner({})
                print >> fd, '    %s;' % self.c_to_java_value('ret','return_value', m.return_arg)
                if m.return_owner:
                    if m.return_type == 'GList*' or m.return_type == 'const GList*':
                        print >> fd, '    free_glist(&return_value, NULL);'
                    elif is_cstring(m.return_type) and not is_const(m.return_arg):
                        print >> fd, '    if (return_value)'
                        print >> fd, '        g_free(return_value);'
            print >> fd, '    return ret;'
        print >> fd, '  }'

    def generate_wrapper_getter(self, c, m, fd):
        type = arg_type(m)
        name = arg_name(m)
        klass = c.name
        prefix = self.JNI_member_function_prefix(c,m)
        return_type = self.jni_return_type(m)
        signature = wrapper_decl("%s_get" % prefix, return_type)
        field = 'gobj->%s' % name
        d = locals()
        print >>fd, '''
/* Getter for %(type)s %(klass)s.%(name)s */
%(signature)s, jobject jobj)  {
    %(klass)s *gobj = NULL;
    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);''' % d
        if debug:
            print >> fd, '    printf("%(prefix)s_get %%p %%p\\n", gobj, %(field)s);' % d
        print >> fd, '    %(return_type)s ret = 0;' % d
        print >> fd, '    if (gobj) {'
        print >> fd, '         %s;' % self.c_to_java_value ('ret', d['field'], m)
        print >> fd, '''    } else {
                 throw_by_name(env, "java/lang/NullPointerException", "no gobject correspond to the given object");
            }
            return ret;
        }
'''

    def generate_wrapper_setter(self, c, m, fd):
        type = arg_type(m)
        name = arg_name(m)
        klass = c.name
        prefix = self.JNI_member_function_prefix(c,m)
        return_type = self.jni_return_type(m)
        signature = wrapper_decl("%s_set" % prefix, 'void')
        field = 'gobj->%s' % name
        d = locals()

        print >> fd,'/* Setter for %(type)s %(klass)s.%(name)s */' % d
        print >> fd, '%(signature)s, jobject jobj, %(return_type)s value)\n  {' % d
        print >> fd, '    %(klass)s *gobj = NULL;' % d
        if debug:
            print >> fd, '    printf("%(prefix)s_set %%p %%p\\n", gobj, value);' % d
        print >> fd, '    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);'
        print >> fd, '    if (!gobj) {'
        print >> fd, '        throw_by_name(env, "java/lang/NullPointerException", "no gobject correspond to the given object");'
        print >> fd, '    }'
        print >> fd, '    %s' % self.java_to_c_value(d['field'], 'value', m, full = True)
        print >> fd, '}'

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

        print >> fd,'/* Adder for %(type)s<%(el_type)s> %(klass)s.%(name)s */' % d
        print >> fd, '%(signature)s, jobject jobj, %(jni_el_type)s value)\n  {' % d
        print >> fd, '    %(klass)s *gobj = NULL;' % d
        print >> fd, '    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);'
        if is_cstring(el_type):
            print >> fd, '    add_to_list_of_strings(env, &%(field)s, value);' % d
        elif is_xml_node(el_type):
            print >> fd, '    add_to_list_of_xml_nodes(env, &%(field)s, value);' % d
        elif is_object(el_type):
            print >> fd, '    add_to_list_of_objects(env, &%(field)s, value);' % d
        else:
            raise Exception('generate_wrapper_adder failed for %s.%s' % (c,m))
        print >> fd, '}'

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
            print >>sys.stderr, 'W: remove for list of xml node not supported: %s' % (m,)
            return
        print >> fd,'/* Remover for %(type)s<%(el_type)s> %(klass)s.%(name)s */' % d
        print >> fd, '%(signature)s, jobject jobj, %(jni_el_type)s value)\n  {' % d
        print >> fd, '    %(klass)s *gobj = NULL;' % d
        print >> fd, '    jobject_to_gobject_noref(env, jobj, (GObject**)&gobj);'
        if is_cstring(el_type):
            print >> fd, '    remove_from_list_of_strings(env, &%(field)s,value);' % d
        elif is_object(el_type):
            print >> fd, '    remove_from_list_of_objects(env, &%(field)s,value);' % d
        else:
            raise Exception('remove_from_list unsupported for %s.%s' % (c,m,))
        print >> fd, '}'
        print >> fd, ''

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
        print >> fd, '        if (errorCode == LassoConstants.%s) {' % orig[6:]
        print >> fd, '            throw new %s(errorCode);' % name
        print >> fd, '        }'

    def generate_exception_classes(self):
        efd = open(lasso_java_path + 'LassoException.java', 'w')
        print >> efd, open(os.path.join(self.src_dir,'LassoException_top.java')).read()
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
        print >> efd, '        throw new LassoException(errorCode, "Uknown lasso error code, maybe a bug in the binding, report it!");'
        print >> efd, '    }'
        print >> efd, '}'
        efd.close()


    def generate_exception_class(self, name, super,abstract,orig):
            fd = open(lasso_java_path + '%s.java' % name, 'w')
            print >> fd, 'package %s;' % lasso_package_name
            print >> fd, ''
            if abstract:
                print >> fd, 'abstract ',
            print >> fd, 'public class %s extends %s {' % (name,super)
            print >> fd, '    private static final long serialVersionUID = 6170037639785281128L;'
            if not abstract:
                print >> fd, '    public %s() {' % name
                print >> fd, '       super(LassoConstants.%s);' % orig[6:]
                print >> fd, '    }'
            print >> fd, '    protected %s(int errorCode) {' % name
            print >> fd, '        super(errorCode);'
            print >> fd, '    }'
            print >> fd, '}'
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
            print >> fd, 'package %s;' % lasso_package_name
            do_import_util = 0
            for m in c.members:
                if m[0] in ('const GList*','GList*','GHashTable*'):
                    do_import_util = 1
            for m in c.methods:
                if m.return_type in ('const GList*','GList*','GHashTable*'):
                    do_import_util = 1
            if do_import_util:
                print >> fd, 'import java.util.*;'
            print >> fd, ''
            print >> fd, 'public class %s extends %s {' % (class_name,parent_name)
            # Constructeur private
            print >> fd, '    /* Constructors */'
            print >> fd, '    protected %s(long cptr) {' % class_name
            print >> fd, '        super(cptr);'
            print >> fd, '    }'
            # Constructeur de base
            def cprefix(name):
                i = name.find('_new')
                if i == -1:
                    return name
                else:
                    return name[:i].replace('_','').lower()
            cons = [ x for x in self.binding_data.functions if cprefix(x.name) == c.name.lower() and x.name.endswith('_new') ]
            for m in cons:
                print >> fd, '    public %s(%s) {' % (class_name, generate_arg_list(self,m.args))
                print >> fd, '        super(LassoJNI.%s(%s));' % (self.JNI_function_name(m),generate_arg_list2(m.args))
                print >> fd, '    }'
            # Constructeurs speciaux
            cons = [ x for x in self.binding_data.functions if cprefix(x.name) == c.name.lower() and not x.name.endswith('_new') ]
            for m in cons:
                name = method_name(m,class_name)
                print >> fd, '    static public %s %s(%s) {' % (class_name, name, generate_arg_list(self,m.args))
                print >> fd, '        return (%s) LassoJNI.%s(%s);' % (class_name, self.JNI_function_name(m),generate_arg_list2(m.args))
                print >> fd, '    }'
            print >> fd, '    /* Setters and getters */'
            for m in c.members:
                type, name, options = m
                prefix = self.JNI_member_function_prefix(c,m)
                jname = format_as_camelcase(name)
                jname = jname[0].capitalize() + jname[1:]
                old_jname = old_format_as_camelcase('_' + name)
                jtype = self.JNI_member_type(m)
                if type == 'GList*' or type == 'const GList*':
                    print >> fd, '    public void set%s(List list) {' % jname
                    print >> fd, '        %s[] arr = null;' % jtype
                    print >> fd, '        if (list != null) {'
                    print >> fd, '            arr = new %s[list.size()];' % jtype
                    print >> fd, '            listToArray(list, arr);'
                    print >> fd, '        }'
                    print >> fd, '        LassoJNI.%s_set(this, arr);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public List get%s() {' % jname
                    print >> fd, '        %s[] arr = LassoJNI.%s_get(this);' % (jtype,prefix)
                    print >> fd, '        if (arr != null)'
                    print >> fd, '            return Arrays.asList(arr);'
                    print >> fd, '        else'
                    print >> fd, '            return new ArrayList(0);'
                    print >> fd, '    }'
                    print >> fd, '    public void addTo%s(%s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_add(this, value);' % prefix
                    print >> fd, '    }'
                    if m[2].get('element-type') not in ('xmlNode*',):
                        print >> fd, '    public void removeFrom%s(%s value) {' % (jname,jtype)
                        print >> fd, '        LassoJNI.%s_remove(this, value);' % prefix
                        print >> fd, '    }'
                    if old_jname != jname:
                        print >> fd, '    public void set%s(List list) {' % old_jname
                        print >> fd, '        this.set%s(list);' % jname
                        print >> fd, '    }'
                        print >> fd, '    public List get%s() {' % old_jname
                        print >> fd, '        return this.get%s();' % jname
                        print >> fd, '    }'
                        print >> fd, '    public void addTo%s(%s value) {' % (old_jname,jtype)
                        print >> fd, '        this.addTo%s(value);' % jname
                        print >> fd, '    }'
                        if m[2].get('element-type') not in ('xmlNode*',):
                            print >> fd, '    public void removeFrom%s(%s value) {' % (old_jname,jtype)
                            print >> fd, '        this.removeFrom%s(value);' % jname
                            print >> fd, '    }'
                elif type == 'GHashTable*':
                    print >> fd, '    public void set%s(Map map) {' % jname
                    print >> fd, '        %s[] arr = null;' % jtype
                    print >> fd, '        if (map != null) {'
                    print >> fd, '            arr = new %s[map.size()*2];' % jtype
                    print >> fd, '            mapToArray(map,arr);'
                    print >> fd, '        }'
                    print >> fd, '        LassoJNI.%s_set(this, arr);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public Map get%s() {' % jname
                    print >> fd, '        return arrayToMap(LassoJNI.%s_get(this));' % prefix
                    print >> fd, '    }'
                else:
                    print >> fd, '    public void set%s(%s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_set(this, value);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public %s get%s() {' % (jtype,jname)
                    print >> fd, '        return LassoJNI.%s_get(this);' % prefix
                    print >> fd, '    }'
                    if old_jname != jname:
                        print >> fd, '    public void set%s(%s value) {' % (old_jname,jtype)
                        print >> fd, '        this.set%s(value);' % jname
                        print >> fd, '    }'
                        print >> fd, '    public %s get%s() {' % (jtype,old_jname)
                        print >> fd, '        return this.get%s();' % jname
                        print >> fd, '    }'
            print >> fd, '    /* Methods */'
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
                        print >> fd, first
                    else:
                        print >> fd, '    /**\n'
                    print >> fd, '      *'
                    for p in doc.parameters:
                        name = p[0]
                        desc = p[1]
                        print >> fd, normalize(desc, '      * @param %s ' % format_as_camelcase(name))
                    if doc.return_value:
                        print >> fd, normalize(doc.return_value, '      * @return ')
                    if m.errors:
                        for err in m.errors:
                            err = error_to_exception(err)[0]
                            print >> fd, normalize(err,'      * @throws ')
                    print >> fd, '    **/'
                outarg = None
                for a in args:
                    if is_out(a):
                        # only one output arg supported
                        assert not outarg
                        outarg = a
                if outarg:
                    assert is_int(make_arg(m.return_type), self.binding_data)
                    new_return_type = self.JNI_return_type(var_type(outarg))
                    print >> fd, '    public %s %s(%s) {' % (new_return_type, mname, generate_arg_list(self, args[1:]))
                    print >> fd, '        Object[] output = new Object[1];'
                    print >> fd, '        LassoException.throwError(LassoJNI.%s(this, %s));' % (jni_name, generate_arg_list2(args[1:]))
                    print >> fd, '        return (%s)output[0];' % new_return_type
                    print >> fd, '    }'

                elif m.return_type == 'GList*' or m.return_type == 'const GList*':
                    print >> fd, '    public List %s(%s) {' % (mname,generate_arg_list(self,args[1:]))
                    arglist = generate_arg_list2(args[1:])
                    if arglist:
                        arglist = ', ' + arglist
                    print >> fd, '        Object[] arr = LassoJNI.%s(this%s);' % (jni_name,arglist)
                    print >> fd, '        if (arr != null)'
                    print >> fd, '            return Arrays.asList(arr);'
                    print >> fd, '        else'
                    print >> fd, '            return null;'
                    print >> fd, '    }'
                else:
                    print >> fd, '    public %s %s(%s) {' % (return_type,mname,generate_arg_list(self,args[1:]))
                    print >> fd, '       ',
                    if m.return_type:
                        print >> fd, 'return',
                    arglist = generate_arg_list2(args[1:])
                    if arglist:
                        arglist = ', ' + arglist
                    if is_rc(m.return_type):
                        print >> fd, 'LassoException.throwError(',
                    print >> fd,'LassoJNI.%s(this%s)' % (jni_name,arglist),
                    if is_rc(m.return_type):
                        print >> fd, ');'
                    else:
                        print >> fd, ';'
                    print >> fd, '    }'
            print >> fd, '}'
            fd.close()
