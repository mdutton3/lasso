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

import utils

lasso_package_name = 'com.entrouvert.lasso'
lasso_java_path = 'com/entrouvert/lasso/'

debug = 0

def with_return_owner(d):
    c = d.copy()
    c['return_owner'] = 1
    return c

def generate_arg_list(self,args):
    def arg_to_decl(arg):
        type, name, option = arg
        return self.JNI_arg_type(type) + ' ' + utils.format_as_camelcase(name)
    return ', '.join([ arg_to_decl(x) for x in args ])

def generate_arg_list2(args):
    def arg_to_decl(arg):
        type, name, option = arg
        return utils.format_as_camelcase(name)
    return ', '.join([ arg_to_decl(x) for x in args ])

def convert_class_name(lasso_name):
    return lasso_name[5:]

def mangle_name(name):
    s = name
    s = s.replace('_', '_1')
    s = s.replace(';', '_2')
    s = s.replace('[', '_3')
    return s

def jni_elem_type(type):
    if type in ('char*', 'gchar*', 'const char*', 'const gchar*'):
        return 'jstring'
    elif type == 'xmlNode*':
        return 'jstring'
    else:
        return 'jobject'

def JNI_elem_type(type):
    if type in ('char*', 'gchar*', 'const char*', 'const gchar*'):
        return 'String'
    elif type == 'xmlNode*':
        return 'String'
    elif type != None and type.startswith('Lasso'):
        return type[5:]
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
    super = utils.format_as_camelcase(super.lower())
    name = utils.format_as_camelcase(name.lower())
    return (super+name+'Exception',super+'Exception')

def wrapper_decl(name, jnitype, fd):
    jniname = wrapper_name(name)
    print >> fd, 'JNIEXPORT %s JNICALL %s(JNIEnv *env, jclass clss' % \
     (jnitype,jniname),

def is_collection(type):
    return type in ('GList*','GHashTable*')

def is_string_type(type):
    return type in ['char*', 'const char*', 'gchar*', 'const gchar*']

def is_const_type(type):
    return type in ['const char*', 'const gchar*']

class JavaBinding:
    def __init__(self, binding_data):
        self.binding_data = binding_data

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
    
    def is_int_type(self, type):
        return type in ['gboolean','int','gint'] + self.binding_data.enums


    def is_gobject_type(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*',
                'GList*', 'GHashTable*',
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

    def JNI_arg_type(self, vtype):
        if vtype == 'gboolean':
            return 'boolean'
        elif vtype in ['int','gint'] + self.binding_data.enums:
            return 'int'
        elif vtype in ('char*', 'gchar*', 'const char*', 'const gchar*'):
            return 'String'
        elif vtype in ('GList*','GHashTable*'):
            return 'Object[]'
        elif vtype == 'xmlNode*':
            return 'String'
        elif isinstance(vtype,basestring) and vtype.startswith('Lasso'):
            if vtype.endswith('*'):
                vtype = vtype[:-1]
            return convert_class_name(vtype)
        else:
            return 'GObject'

    def JNI_return_type(self, vtype):
        if vtype == 'gboolean':
            return 'boolean'
        elif vtype in ['int','gint'] + self.binding_data.enums:
            return 'int'
        elif vtype in ('char*', 'gchar*', 'const char*', 'const gchar*'):
            return 'String'
        elif vtype in ('GList*','GHashTable*'):
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
        type, name, options = member
        if type in ('GList*','GHashTable*'):
            return self.JNI_arg_type(options.get('elem_type'))
        else:
            return self.JNI_arg_type(type)

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
        print >> fd, '   public static native %s %s(%s);' % (jtype,name, generate_arg_list(self,m.args))

    def JNI_member_function_prefix(self,c,m):
        klassname = c.name[5:]
        mname = utils.format_as_camelcase(m[1])
        return '%s_%s' % (klassname,mname)

    def generate_JNI_member(self, c, fd):
        for m in c.members:
            prefix = self.JNI_member_function_prefix(c,m)
            mname = utils.format_as_camelcase(m[1])
            mtype = m[0]

            jtype = self.JNI_member_type(m)
            if mtype == 'GList*':
                name = '%s_get' % prefix
                print >> fd, '   public static native %s[] %s(GObject obj);' % (jtype,name)
                name = '%s_set' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s[] value);' % (name,jtype)
                name = '%s_add' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s value);' % (name,jtype)
                if not m[2].get('elem_type') in ('xmlNode*',): 
                    name = '%s_remove' % prefix
                    print >> fd, '   public static native void %s(GObject obj, %s value);' % (name,jtype)
            elif mtype == 'GHashTable*':
                name = '%s_get' % prefix
                print >> fd, '   public static native %s[] %s(GObject obj);' % (jtype,name)
                name = '%s_set' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s[] value);' % (name,jtype)
                name = '%s_add' % prefix
                print >> fd, '   public static native void %s(GObject obj, String key, %s value);' % (name,jtype)
#                name = '%s_remove' % prefix
#                print >> fd, '   public static native void %s(GObject obj, String key);' % (name)
#                name = '%s_get_by_name' % prefix
#                print >> fd, '   public static native %s[] %s(GObject obj, String key);' % (jtype,name)
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
        print >> fd, open(os.path.join(self.binding_data.src_dir,
                    'lang_java_wrapper_bottom.c')).read()
        fd.close()

    def generate_wrapper_header(self, fd):
        print >> fd, open(os.path.join(self.binding_data.src_dir, 
                    'lang_java_wrapper_top.c')).read()
        print >> fd, ''
        for h in self.binding_data.headers:
            print >> fd, '#include <%s>' % h


    def generate_wrapper_constants(self, fd):
        print >> fd, '/* Declaration of constants */'
        for c in self.binding_data.constants:
            s = c[1]+'_get'
            if c[0] == 'i':
                wrapper_decl(s,'jint',fd)
                print >>fd, ') {'
                print >>fd, '   return %s;' % c[1]
                print >>fd, '}'
            elif c[0] == 's':
                wrapper_decl(s,'jstring',fd)
                print >>fd, ') {'
                print >>fd, '   return (*env)->NewStringUTF(env, %s);' % c[1]
                print >>fd, '}'
            elif c[0] == 'b':
                wrapper_decl(s,'jboolean',fd)
                print >>fd, ') {'
                print >>fd, '#ifdef %s' % c[1]
                print >>fd, '   return 1;'
                print >>fd, '#else'
                print >>fd, '   return 0;'
                print >>fd, '#endif'
                print >>fd, '}'
        print >> fd, '/* End of declaration of constants */'

    def jni_return_type(self, type):
        if type == 'gboolean':
            return 'jboolean'
        elif type in ['int','gint'] + self.binding_data.enums:
            return 'jint'
        elif type in ('char*', 'gchar*', 'const char*', 'const gchar*'):
            return 'jstring'
        elif type in ('GList*','GHashTable*'):
            return 'jobjectArray'
        elif type == 'xmlNode*':
            return 'jstring'
        elif not type:
            return 'void'
        else:
            return 'jobject'

    def c_to_java_value(self, left, right, type, options):
        if type == 'gboolean':
            return '%s = (jboolean)%s' % (left,right)
        elif type in ['int', 'gint'] + self.binding_data.enums:
            return '%s = (jint)%s' % (left, right)
        elif is_string_type(type):
            return 'string_to_jstring(env, %s, &%s)' % (right, left)
        elif type in ('GList*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'get_list_of_strings(env, %s, &%s)' % (right, left)
            elif elem_type == 'xmlNode*':
                return 'get_list_of_xml_nodes(env, %s, &%s)' % (right, left)
            else:
                return 'get_list_of_objects(env, %s, &%s)' % (right, left)
        elif type in ('GHashTable*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'get_hash_of_strings(env, %s, &%s)' % (right, left)
            else:
                return 'get_hash_of_objects(env, %s, &%s)' % (right, left)
        elif type == 'xmlNode*':
                return 'xml_node_to_jstring(env, %s, &%s)' % (right, left)
        else:
            if options.get('return_owner'):
                return 'gobject_to_jobject(env, (GObject*)%s, &%s);' % (right, left)
            else:
                return 'gobject_to_jobject_and_ref(env, (GObject*)%s, &%s);' % (right, left)

    def java_to_c_value(self, left, right, type, options):
        if type in ['gboolean','int', 'gint'] + self.binding_data.enums:
            return '%s = (%s)%s;' % (left,type,right)
        elif is_string_type(type):
            return 'jstring_to_string(env, %s, (char**)&%s);' % (right,left)
        elif type in ('GList*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'set_list_of_strings(env, &%s,%s);' % (left,right)
            elif elem_type == 'xmlNode*':
                return 'set_list_of_xml_nodes(env, &%s, %s);' % (left, right)
            else:
                return 'set_list_of_objects(env, &%s, %s);' % (left, right)
        elif type in ('GHashTable*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'set_hash_of_strings(env, %s, %s);' % (left,right)
            else:
                return 'set_hash_of_objects(env, %s, %s);' % (left,right)
        elif type == 'xmlNode*':
            return 'jstring_to_xml_node(env, %s, &%s);' % (right, left)
        else:
            return 'jobject_to_gobject(env, %s, (GObject**)&%s);' % (right, left)

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
        wrapper_decl(name, jtype, fd)
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
            print >> fd, '    %s %s;' % (arg_type.replace('const ',''),arg_name)
        # Declare return vars
        if m.return_type:
            print >> fd, '    %s return_value;' % m.return_type
        idx = 0
        # Convert args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            print >> fd, '    %s' % self.java_to_c_value(arg_name, 'jarg%s' % idx, arg_type, arg_options)
        if debug:
            print >> fd, '    printf("%s' % name,
            arglist = ''
            for  arg in m.args:
                arg_type, arg_name, arg_options = arg
                arglist = arglist + ', %s' % arg_name
                if self.is_int_type(arg_type):
                    print >> fd, '%i',
                elif is_string_type(arg_type):
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

        print >> fd, '%s(%s);' % (m.name, ', '.join([x[1] for x in m.args]))
        # Free const char * args
        idx=0
        for arg in m.args:
            idx=idx+1
            arg_type, arg_name, arg_options = arg
            if is_string_type(arg_type):
                print >> fd, '    if (%s)' % arg_name
                print >> fd, '        g_free(%s);' % arg_name
            elif arg_type == 'GList*':
                if arg_options.get('elem_type') == 'char*':
                    print >> fd, '    free_glist(&%s, (GFunc)free);' % arg_name
                else:
                    raise Exception('Freeing args of type list of \'%s\' not supported.' % arg_options.get('elem_type'))

        # Return
        if m.return_type:
            if m.name.endswith('_new'):
                print >> fd, '    ret = (jlong)(int) return_value;'
            else:
                options = {}
                if m.return_owner:
                    options = with_return_owner({})
                print >> fd, '    %s;' % self.c_to_java_value('ret','return_value', m.return_type, options)
                if m.return_owner:
                    if m.return_type == 'GList*':
                        print >> fd, '    free_glist(&return_value, NULL);'
                    elif is_string_type(m.return_type) and not is_const_type(m.return_type):
                        print >> fd, '    if (return_value)'
                        print >> fd, '        g_free(return_value);'
            print >> fd, '    return ret;'
        print >> fd, '  }'

    def generate_wrapper_getter_setter(self, c, fd):
        klassname = c.name
        for m in c.members:
            mtype = m[0]
            prefix = self.JNI_member_function_prefix(c,m)
            # getter
            jtype = self.jni_return_type(mtype)
            print >> fd,'/* Getter for %s %s.%s */' % (mtype,klassname,m[1])
            wrapper_decl("%s_get" % prefix, jtype, fd)
            print >> fd, ', jobject jobj)\n  {'
            print >> fd, '    %s *gobj;' % klassname
            print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
            if debug:
                print >> fd, '    printf("%s_get %%p %%p\\n", gobj, gobj->%s);' % (prefix, m[1])
            print >> fd, '    %s ret = 0;' % jtype
            print >> fd, '    if (gobj) {'
            print >> fd, '         %s;' % self.c_to_java_value ('ret','gobj->%s' % m[1], mtype, m[2])
            print >> fd, '    } else {'
            print >> fd, '         (*env)->ThrowNew(env, "java/lang/NullPointerException", "no gobject correspond to the given object");'
            print >> fd, '    }'
            print >> fd, '    return ret;'
            print >> fd, '}'
            print >> fd, ''
            # setter
            print >> fd,'/* Setter for %s %s.%s */' % (mtype,klassname,m[1])
            wrapper_decl("%s_set" % prefix, 'void', fd)
            print >> fd, ', jobject jobj, %s value)\n  {' % self.jni_return_type(mtype)
            print >> fd, '    %s *gobj;' % klassname
            if debug:
                print >> fd, '    printf("%s_set %%p %%p\\n", gobj, value);' % prefix
            print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
            print >> fd, '    if (!gobj) {'
            print >> fd, '        (*env)->ThrowNew(env, "java/lang/NullPointerException", "no gobject correspond to the given object");'
            print >> fd, '    }'
            if not self.is_int_type(mtype) and not is_collection(mtype):
                print >> fd, '    if (gobj->%s) {' % m[1]
                if is_string_type(mtype):
                    print >> fd, '    g_free(gobj->%s);' % m[1]
                else:
                    print >> fd, '    g_object_unref(gobj->%s);' % m[1]
                print >> fd, '    }'
            print >> fd, '    %s' % self.java_to_c_value('gobj->%s' % m[1], 'value', mtype, m[2])
            if self.is_gobject_type(mtype):
                print >> fd, '    if (gobj->%s) {' % m[1]
                print >> fd, '         g_object_ref(gobj->%s);' % m[1]
                print >> fd, '    }'
            print >> fd, '}'
            # add/remove
            if mtype in ('GList*', ):
                # add
                print >> fd,'/* Adder for %s %s.%s */' % (mtype,klassname,m[1])
                elem_type = m[2].get('elem_type')
                wrapper_decl("%s_add" % prefix, 'void', fd)
                print >> fd, ', jobject jobj, %s value)\n  {' % jni_elem_type(elem_type)
                print >> fd, '    %s *gobj;' % klassname
                print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
                if is_string_type(elem_type):
                    print >> fd, '    add_to_list_of_strings(env, &gobj->%s,value);' % m[1]
                elif elem_type in ('xmlNode*',):
                    print >> fd, '    add_to_list_of_xml_nodes(env, &gobj->%s,value);' % m[1]
                else:
                    print >> fd, '    add_to_list_of_objects(env, &gobj->%s,value);' % m[1]
                print >> fd, '}'
                # remove
                if elem_type not in ('xmlNode*',):
                    print >> fd,'/* Remover for %s %s.%s */' % (mtype,klassname,m[1])
                    wrapper_decl("%s_remove" % prefix, 'void', fd)
                    print >> fd, ', jobject jobj, %s value)\n  {' % jni_elem_type(elem_type)
                    print >> fd, '    %s *gobj;' % klassname
                    print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
                    if elem_type in ('char*','gchar*'):
                        print >> fd, '    remove_from_list_of_strings(env, &gobj->%s,value);' % m[1]
                    else:
                        print >> fd, '    remove_from_list_of_objects(env, &gobj->%s,value);' % m[1]
                    print >> fd, '}'
            # add/remove/get_by_name
            if mtype in ('GHashTable*',):
                # add
                print >> fd,'/* Adder for %s %s.%s */' % (mtype,klassname,m[1])
                elem_type = m[2].get('elem_type')
                wrapper_decl("%s_add" % prefix, 'void', fd)
                print >> fd, ', jobject jobj, jstring key, %s value)\n  {' % jni_elem_type(elem_type)
                print >> fd, '    %s *gobj;' % klassname
                print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
                if elem_type in ('char*','gchar*'):
                    print >> fd, '    add_to_hash_of_strings(env, gobj->%s,value,key);' % m[1]
                else:
                    print >> fd, '    add_to_hash_of_objects(env, gobj->%s,value,key);' % m[1]
                print >> fd, '}'
#                # remove
#                print >> fd,'/* Remover for %s %s.%s */' % (mtype,klassname,m[1])
#                wrapper_decl("%s_remove" % prefix, 'void', fd)
#                print >> fd, ', jobject jobj, jstring key)\n  {'
#                print >> fd, '    %s *gobj;' % klassname
#                print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
#                if elem_type in ('char*','gchar*'):
#                    print >> fd, '    remove_from_hash_of_strings(env, gobj->%s,key);' % m[1]
#                else:
#                    print >> fd, '    remove_from_hash_of_objects(env, gobj->%s,key);' % m[1]
#                print >> fd, '}'
#                # get by name
#                print >> fd,'/* Get by name for %s %s.%s */' % (mtype,klassname,m[1])
#                wrapper_decl("%s_get_by_name" % prefix, jni_elem_type(elem_type) , fd)
#                print >> fd, ', jobject jobj, jstring key)\n  {'
#                print >> fd, '    %s *gobj;' % klassname
#                print >> fd, '    jobject_to_gobject(env, jobj, (GObject**)&gobj);'
#                if elem_type in ('char*','gchar*'):
#                    print >> fd, '    return get_hash_of_strings_by_name(env, gobj->%s,key);' % m[1]
#                else:
#                    print >> fd, '    return get_hash_of_objects_by_name(env, gobj->%s,key);' % m[1]
#                print >> fd, '}'

#
    def generate_exception_switch_case(self, fd, name, orig):
        print >> fd, '        if (errorCode == LassoConstants.%s) {' % orig[6:]
        print >> fd, '            throw new %s(errorCode);' % name
        print >> fd, '        }'

    def generate_exception_classes(self):
        efd = open(lasso_java_path + 'LassoException.java', 'w')
        print >> efd, open(os.path.join(self.binding_data.src_dir, 
                    'java/LassoException_top.java')).read()
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
            name = utils.format_underscore_as_camelcase(name)
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
                name = utils.format_as_camelcase(m.name[6:])
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
                if m[0] in ('GList*','GHashTable*'):
                    do_import_util = 1
            for m in c.methods:
                if m.return_type in ('GList*','GHashTable*'):
                    do_import_util = 1
            if do_import_util:
                print >> fd, 'import java.util.*;'
            print >> fd, ''
            #print 'class %s extends %s {' % (class_name,parent_name)
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
            #print 'cons ', cons
            for m in cons:
                print >> fd, '    public %s(%s) {' % (class_name, generate_arg_list(self,m.args))
                print >> fd, '        super(LassoJNI.%s(%s));' % (self.JNI_function_name(m),generate_arg_list2(m.args))
                print >> fd, '    }'
            # Constructeurs speciaux
            cons = [ x for x in self.binding_data.functions if cprefix(x.name) == c.name.lower() and not x.name.endswith('_new') ]
            #print 'cons ', cons
            for m in cons:
                name = method_name(m,class_name)
                print >> fd, '    static public %s %s(%s) {' % (class_name, name, generate_arg_list(self,m.args))
                print >> fd, '        return LassoJNI.%s(%s);' % (self.JNI_function_name(m),generate_arg_list2(m.args))
                print >> fd, '    }'
            print >> fd, '    /* Setters and getters */'
            for m in c.members:
                type, name, options = m
                prefix = self.JNI_member_function_prefix(c,m)
                jname = utils.format_as_camelcase('_'+name)
                jtype = self.JNI_member_type(m)
                if type == 'GList*':
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
                    print >> fd, '            return null;'
                    print >> fd, '    }'
                    print >> fd, '    public void addTo%s(%s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_add(this, value);' % prefix
                    print >> fd, '    }'
                    if m[2].get('elem_type') not in ('xmlNode*',):
                        print >> fd, '    public void removeFrom%s(%s value) {' % (jname,jtype)
                        print >> fd, '        LassoJNI.%s_remove(this, value);' % prefix
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
                    print >> fd, '    public void addTo%s(String key, %s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_add(this, key, value);' % prefix
                    print >> fd, '    }'
#                    print >> fd, '    public void removeFrom%s(String key) {' % (jname)
#                    print >> fd, '        LassoJNI.%s_remove(this, key);' % prefix
#                    print >> fd, '    }'
                    #print '  void set%s(%s[] value)' % (jname,jtype)
                    #print '  %s[] get%s()' % (jtype,jname)
                    #print '  void addTo%s(String key, %s value)' % (jname,jtype)
                    #print '  void removeFrom%s(String key)' % (jname,jtype)
                    #print '  %s get%sByName(String key)' % (jtype,jname)
                else:
                    print >> fd, '    public void set%s(%s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_set(this, value);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public %s get%s() {' % (jtype,jname)
                    print >> fd, '        return LassoJNI.%s_get(this);' % prefix
                    print >> fd, '    }'
                    #print '  void set%s(%s value)' % (jname,jtype)
                    #print '  %s get%s()' % (jtype,jname)
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
                    for name, desc in doc.parameters:
                        print >> fd, normalize(desc, '      * @param %s ' % utils.format_as_camelcase(name))
                    if doc.return_value:
                        print >> fd, normalize(doc.return_value, '      * @return ')
                    if m.errors:
                        for err in m.errors:
                            err = error_to_exception(err)[0]
                            print >> fd, normalize(err,'      * @throws ')
                    print >> fd, '    **/'
                if m.return_type == 'GList*':
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
                    if m.errors:
                        print >> fd, 'LassoException.throwError(',
                    print >> fd,'LassoJNI.%s(this%s)' % (jni_name,arglist),
                    if m.errors:
                        print >> fd, ');'
                    else:
                        print >> fd, ';'
                    print >> fd, '    }'
            print >> fd, '}'
            fd.close()
