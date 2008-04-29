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

class JavaBinding:
    def __init__(self, binding_data):
        self.binding_data = binding_data

    def is_pygobject(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*',
                'GList*', 'GHashTable*',
                'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

    def generate(self):
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
	    print >> fd, '%s = LassoJNI.%s_get();' % (c[1], c[1])

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
public static native void init2();
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
                name = '%s_remove' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s value);' % (name,jtype)
            elif mtype == 'GHashTable*':
                name = '%s_get' % prefix
                print >> fd, '   public static native %s[] %s(GObject obj);' % (jtype,name)
                name = '%s_set' % prefix
                print >> fd, '   public static native void %s(GObject obj, %s[] value);' % (name,jtype)
                name = '%s_add' % prefix
                print >> fd, '   public static native void %s(GObject obj, String key, %s value);' % (name,jtype)
                name = '%s_remove' % prefix
                print >> fd, '   public static native void %s(GObject obj, String key);' % (name)
                name = '%s_get_by_name' % prefix
                print >> fd, '   public static native %s[] %s(GObject obj, String key);' % (jtype,name)
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

    def jni_return_type(self, vtype):
        if vtype == 'gboolean':
            return 'jboolean'
        elif vtype in ['int','gint'] + self.binding_data.enums:
            return 'jint'
        elif vtype in ('char*', 'gchar*', 'const char*', 'const gchar*'):
            return 'jstring'
        elif vtype in ('GList*','GHashTable*'):
            return 'jobjectArray'
        elif vtype == 'xmlNode*':
            return 'jstring'
        elif not vtype:
            return 'void'
        else:
            return 'jobject'

    def c_to_java_value(self, name, vtype, options):
        if vtype == 'gboolean':
            return '(jboolean)%s' % name
        elif vtype in ['int', 'gint'] + self.binding_data.enums:
            return '(jint)%s' % name
        elif vtype in ('char*', 'gchar*'):
            return 'string_to_jstring(env, %s)' % name
        elif vtype in ('const char*', 'const gchar*'):
            return 'string_to_jstring(env, %s)' % name
        elif vtype in ('GList*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'get_list_of_strings(env, %s)' % name
            elif elem_type == 'xmlNode*':
                return 'get_list_of_xml_nodes(env, %s)' % name
            else:
                return 'get_list_of_objects(env, %s)' % name
        elif vtype in ('GHashTable*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'get_hash_of_strings(env, %s)' % name
            else:
                return 'get_hash_of_objects(env, %s)' % name
        elif vtype == 'xmlNode*':
                return 'xml_node_to_jstring(env, %s)' % name
        else:
            if 'return_owner' in options:
                return 'gobject_to_jobject(env, (GObject*)%s);' % name
            else:
                return 'gobject_to_jobject_and_ref(env, (GObject*)%s);' % name

    def java_to_c_value(self, left, right, vtype, options):
        if vtype in ['gboolean','int', 'gint'] + self.binding_data.enums:
            return '%s = (%s)%s;' % (left,vtype,right)
        elif vtype in ('char*', 'gchar*'):
            return '%s = (%s) jstring_to_string_dup(env, %s);' % (left,vtype,right)
        elif vtype in ('const char*', 'const gchar*'):
            return '%s = (%s) jstring_to_string(env, %s);' % (left,vtype,right)
        elif vtype in ('GList*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'set_list_of_strings(env, &%s,%s);' % (left,right)
            elif elem_type == 'xmlNode*':
                return 'set_list_of_xml_nodes(env, &%s, %s);' % (left, right)
            else:
                return 'set_list_of_objects(env, &%s, %s);' % (left, right)
        elif vtype in ('GHashTable*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                return 'set_hash_of_strings(env, %s, %s);' % (left,right)
            else:
                return 'set_hash_of_objects(env, %s, %s);' % (left,right)
        elif vtype == 'xmlNode*':
                return '%s = jstring_to_xml_node(env, %s);' % (left, right)
        else:
            if 'return_owner' in options:
                return '%s = (%s)jobject_to_gobject(env, %s);' % (left,vtype,right)
            else:
                return '%s = (%s)jobject_to_gobject_and_ref(env, %s);' % (left,vtype,right)

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
            print >> fd, '%s ret;' % jtype
        # Declare C args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            print >> fd, '    %s %s;' % (arg_type,arg_name)
        # Declare return vars
        if m.return_type:
            print >> fd, '    %s return_value;' % m.return_type
        idx = 0
        # Convert args
        for arg in m.args:
            idx = idx + 1
            arg_type, arg_name, arg_options = arg
            option = arg_options.copy()
            option['return_owner'] = 1
            print >> fd, '    %s' % self.java_to_c_value(arg_name, 'jarg%s' % idx, arg_type, option)
        # Call function
        print >> fd, '   ',
        if m.return_type:
            print >> fd, 'return_value = (%s)' % m.return_type,
        print >> fd, '%s(%s);' % (m.name, ', '.join([x[1] for x in m.args]))
        options = {}
        # Free const char * args
        idx=0
        for arg in m.args:
            idx=idx+1
            arg_type, arg_name, arg_options = arg
            if  arg_type in ('const gchar*', 'const char*'):
                print >> fd, '    release_utf_string(env, jarg%s, %s);' % (idx,arg_name)

        # Return
        if m.return_type:
            if m.name.endswith('_new'):
                print >> fd, '    return (jlong) return_value;'
            else:
                if m.return_owner:
                    options['return_owner'] = 1
                print >> fd, '    ret = %s;' % self.c_to_java_value('return_value', m.return_type, options)
                if m.return_type == 'GList*' and not m.return_owner:
                    print >> fd, '    free_glist(return_value, NULL);'
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
            print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
            print >> fd, '    if (gobj) {'
            print >> fd, '         return %s;' % self.c_to_java_value ('gobj->%s' % m[1], mtype, m[2])
            print >> fd, '    } else {'
            print >> fd, '         (*env)->ThrowNew(env, "java/lang/NullPointerException", "no gobject correspond to the given object");'
            print >> fd, '         return 0;'
            print >> fd, '    }'
            print >> fd, '}'
            print >> fd, ''
            # setter
            print >> fd,'/* Setter for %s %s.%s */' % (mtype,klassname,m[1])
            wrapper_decl("%s_set" % prefix, 'void', fd)
            print >> fd, ', jobject jobj, %s value)\n  {' % self.jni_return_type(mtype)
            print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
            if mtype in ('char*', 'const char*', 'gchar*', 'const gchar*'):
                print >> fd, '    g_free(gobj->%s);' % m[1]
            print >> fd, '    %s' % self.java_to_c_value('gobj->%s' % m[1], 'value', mtype, m[2])
            print >> fd, '}'
            # add/remove
            if mtype in ('GList*', ):
                # add
                print >> fd,'/* Adder for %s %s.%s */' % (mtype,klassname,m[1])
                elem_type = m[2].get('elem_type')
                wrapper_decl("%s_add" % prefix, 'void', fd)
                print >> fd, ', jobject jobj, %s value)\n  {' % jni_elem_type(elem_type)
                print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
                if elem_type in ('char*','gchar*'):
                    print >> fd, '    add_to_list_of_strings(env, &gobj->%s,value);' % m[1]
                elif elem_type in ('xmlNode*',):
                    print >> fd, '    add_to_list_of_xml_nodes(env, &gobj->%s,value);' % m[1]
                else:
                    print >> fd, '    add_to_list_of_objects(env, &gobj->%s,value);' % m[1]
                print >> fd, '}'
                # remove
                print >> fd,'/* Remover for %s %s.%s */' % (mtype,klassname,m[1])
                wrapper_decl("%s_remove" % prefix, 'void', fd)
                print >> fd, ', jobject jobj, %s value)\n  {' % jni_elem_type(elem_type)
                print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
                if elem_type in ('char*','gchar*'):
                    print >> fd, '    remove_from_list_of_strings(env, &gobj->%s,value);' % m[1]
                elif elem_type in ('xmlNode*',):
                    print >> fd, '    remove_from_list_of_xml_nodes(env, &gobj->%s,value);' % m[1]
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
                print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
                if elem_type in ('char*','gchar*'):
                    print >> fd, '    add_to_hash_of_strings(env, gobj->%s,value,key);' % m[1]
                else:
                    print >> fd, '    add_to_hash_of_objects(env, gobj->%s,value,key);' % m[1]
                print >> fd, '}'
                # remove
                print >> fd,'/* Remover for %s %s.%s */' % (mtype,klassname,m[1])
                wrapper_decl("%s_remove" % prefix, 'void', fd)
                print >> fd, ', jobject jobj, jstring key)\n  {'
                print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
                if elem_type in ('char*','gchar*'):
                    print >> fd, '    remove_from_hash_of_strings(env, gobj->%s,key);' % m[1]
                else:
                    print >> fd, '    remove_from_hash_of_objects(env, gobj->%s,key);' % m[1]
                print >> fd, '}'
                # get by name
                print >> fd,'/* Get by name for %s %s.%s */' % (mtype,klassname,m[1])
                wrapper_decl("%s_get_by_name" % prefix, jni_elem_type(elem_type) , fd)
                print >> fd, ', jobject jobj, jstring key)\n  {'
                print >> fd, '    %s *gobj = (%s*)jobject_to_gobject(env, jobj);' % (klassname,klassname)
                if elem_type in ('char*','gchar*'):
                    print >> fd, '    return get_hash_of_strings_by_name(env, gobj->%s,key);' % m[1]
                else:
                    print >> fd, '    return get_hash_of_objects_by_name(env, gobj->%s,key);' % m[1]
                print >> fd, '}'

#
    def generate_exception_switch_case(self, fd, name, orig):
        print >> fd, '        if (errorCode == LassoConstants.%s) {' % orig
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
            if not abstract:
                print >> fd, '    public %s() {' % name
                print >> fd, '       super(LassoConstants.%s);' % orig
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
                    print >> fd, '    public void set%s(%s[] value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_set(this, value);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public %s[] get%s() {' % (jtype,jname)
                    print >> fd, '        return LassoJNI.%s_get(this);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public void addTo%s(%s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_add(this, value);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public void removeFrom%s(%s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_remove(this, value);' % prefix
                    print >> fd, '    }'
                elif type == 'GHashTable*':
                    print >> fd, '    public void set%s(%s[] value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_set(this, value);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public %s[] get%s() {' % (jtype,jname)
                    print >> fd, '        return LassoJNI.%s_get(this);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public void addTo%s(String key, %s value) {' % (jname,jtype)
                    print >> fd, '        LassoJNI.%s_add(this, key, value);' % prefix
                    print >> fd, '    }'
                    print >> fd, '    public void removeFrom%s(String key) {' % (jname)
                    print >> fd, '        LassoJNI.%s_remove(this, key);' % prefix
                    print >> fd, '    }'
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
                    str = re.sub(r'#Lasso(\w+)',r'{@link \1}',str)
                    str = re.sub(r'[^.]*must *be *freed *by[^.]*\.?', '', str)
                    str = re.sub(r'[^.]*internally[^.]*\.?[^.]*freed[^.]*\.?', '', str)

                    str = re.sub(r'[^.]*\bfreed?\b[^.]*\.?', '', str)
                    str = re.sub(r'(a +)?#?GList\*?','an array', str)
                    return wrapper.fill(re.sub(r'@\b(\w+)\b',r'\1',str))
                if doc:
                    print >> fd, normalize(doc.description, '    /** ')
                    print >> fd, '      *'
                    for name, desc in doc.parameters[1:]:
                        print >> fd, normalize(desc, '      * @param %s ' % utils.format_as_camelcase(name))
                    if doc.return_value:
                        print >> fd, normalize(doc.return_value, '      * @return ')
                    if m.errors:
                        for err in m.errors:
                            err = error_to_exception(err)[0]
                            print >> fd, normalize(err,'      * @throws ')
                    print >> fd, '    **/'
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
