#! /usr/bin/env python
#
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
import re
import sys
from utils import *

from optparse import OptionParser

try:
    from lxml import etree as ET
except ImportError:
    try:
        import cElementTree as ET
    except ImportError:
        try:
            import elementtree.ElementTree as ET
        except ImportError:
            import xml.etree.ElementTree as ET

sys.path.append(os.path.dirname(__file__))

# monkey patch os.path to include relpath if python version is < 2.6
if not hasattr(os.path, "relpath"):
    def relpath(longPath, basePath):
        if not longPath.startswith(basePath):
            raise RuntimeError("Unexpected arguments")
        if longPath == basePath:
            return "."
        i = len(basePath)
        if not basePath.endswith(os.path.sep):
            i += len(os.path.sep)
        return longPath[i:]

    os.path.relpath = relpath



class BindingData:
    src_dir = os.path.dirname(__file__)

    def __init__(self, options = None):
        self.headers = []
        # [(char,string)]
        # where char is:
        # - i: integer
        # - s: string
        self.constants = []
        self.structs = []
        self.struct_dict = {}
        self.functions = []
        self.enums = []
        self.options = options
        self.overrides = ET.parse(os.path.join(self.src_dir, 'overrides.xml'))
        self.functions_toskip = dict()
        self.structs_toskip = dict()

        for func in self.overrides.findall('func'):
            if func.attrib.get('skip') == 'true':
                self.functions_toskip[func.attrib.get('name')] = 1
        for struct in self.overrides.findall('struct'):
            if struct.attrib.get('skip') == 'true':
                self.structs_toskip[struct.attrib.get('name')] = 1

    def match_tag_language(self,tag):
        if self.options and self.options.language:
            languages = tag.attrib.get('language')
            if languages:
                lang_list = languages.split(' ')
                if self.options.language in lang_list:
                    return True
                else:
                    return False
            else:
                return True
        else:
            return True

    def display_structs(self):
        for struct in self.structs:
            struct.display()

    def display_funcs(self):
        for func in self.functions:
            print func.return_type, func.name
            for a in func.args:
                print '  ', a

    def order_class_hierarchy(self):
        new_order = []
        while self.structs:
            for c in self.structs:
                if c.parent == 'GObject' or c.parent in [x.name for x in new_order]:
                    self.structs.remove(c)
                    new_order.append(c)
                    break
        self.structs = new_order

    def create_struct_dict(self):
        for c in self.structs:
            self.struct_dict[c.name] = c

    def attach_methods(self):
        self.create_struct_dict()
        for f in self.functions[:]:
            if len(f.args) == 0:
                continue
            if f.name.endswith('_new') or '_new_' in f.name:
                # constructor for another class
                continue
            arg_type = f.args[0][0]
            if arg_type[-1] == '*':
                arg_type = arg_type[:-1]
            arg_type = arg_type.replace('const ','')
            c = self.struct_dict.get(arg_type)
            if not c:
                continue
            c.methods.append(f)
            if f.docstring and f.docstring.parameters:
                # remove first parameter, which is self/this/etc.
                f.docstring.parameters = f.docstring.parameters[1:]

            self.functions.remove(f)

    def look_for_docstrings(self, srcdir, exception_doc):
        def getfunc(name):
            funcs = [f for f in self.functions if f.name == name]
            if not funcs:
                return None
            else:
                return funcs[0]
        regex = re.compile(r'\/\*\*\s(.*?)\*\/', re.DOTALL)
        for base, dirnames, filenames in os.walk(srcdir):
            bname = os.path.basename(base)
            if bname == '.svn':
                # ignore svn directories
                continue
            if not 'Makefile.am' in filenames:
                # not a source dir
                continue
            makefile_am = open(os.path.join(base, 'Makefile.am')).read()
            filenames = [x for x in filenames if x.endswith('.c') if x in makefile_am]
            for filename in filenames:
                s = open(os.path.join(base, filename)).read()
                docstrings = regex.findall(s)
                for d in docstrings:
                    docstring = '\n'.join([x[3:] for x in d.splitlines()])
                    function_name = docstring.splitlines(1)[0].strip().strip(':')
                    func = getfunc(function_name)
                    if not func:
                        continue
                    func.docstring = DocString(func, docstring, self)
        if exception_doc:
            lines = os.popen('perl ../utility-scripts/error-analyzer.pl %s' % srcdir, 'r').readlines()
            for line in lines:
                elts = re.split(r' +',line.strip())
                func = getfunc(elts[0])
                if func:
                    func.errors = elts[1:]


class Struct:
    def __init__(self, name):
        self.name = name[1:] # skip leading _
        self.parent = None
        self.members = []
        self.methods = []

    def __repr__(self):
        return '<Struct name:%s, childof:%s>' % (self.name, self.parent)

    def display(self):
        print self.__repr__()
        for m in self.members:
            print '  ', m
        for m in self.methods:
            print '  ', m

    def getMember(self, name):
        l = [m for m in self.members if arg_name(m) == name]
        if l:
            return l[0]
        else:
            return None

    def getMethod(self, name):
        l = [m for m in self.methods if m.name == name]
        if l:
            return l[0]
        else:
            return None

toskip = None


class Function:
    return_type = None
    return_type_qualifier = None
    return_arg = None
    name = None
    rename = None
    args = None
    docstring = None
    return_owner = True
    skip = False
    errors = None

    def __repr__(self):
        return '<Function return_type:%s name:%s args:%r>' % (
                self.return_arg, self.name, self.args)

    def apply_overrides(self):
        for func in binding.overrides.findall('func'):
            if not binding.match_tag_language(func):
                continue
            if func.attrib.get('name') != self.name:
                continue
            for param in func.findall('param'):
                try:
                    arg = [x for x in self.args if x[1] == param.attrib.get('name')][0]
                except IndexError:
                    print >> sys.stderr, 'W: no such param (%s) in function (%s)' % (
                            param.attrib.get('name'), self.name)
                    continue
                if param.attrib.get('optional') == 'true':
                    arg[2]['optional'] = True
                if param.attrib.get('default'):
                    arg[2]['default'] = param.attrib.get('default')
                if param.attrib.get('type'):
                    arg[0] = param.attrib.get('type')
                if param.attrib.get('elem_type'):
                    arg[2]['element-type'] = param.attrib.get('elem_type')
            if func.attrib.get('rename'):
                self.rename = func.attrib.get('rename')
            if func.attrib.get('return_owner'):
                self.return_owner = (func.attrib.get('return_owner') != 'false')
            if func.attrib.get('return_type'):
                self.return_type = func.attrib.get('return_type')
            if func.attrib.get('skip'):
                skip = func.attrib.get('skip')
                if skip == 'true':
                    self.skip = True
                elif skip == 'unless-id-wsf' and not binding.options.idwsf:
                    self.skip = True
                elif binding.options.language in skip.split(','):
                    self.skip = True
            if func.attrib.get('return_type_qualifier'):
                self.return_type_qualifier = func.attrib.get('return_type_qualifier')
        for param in binding.overrides.findall('arg'):
            if not binding.match_tag_language(param):
                continue
            arg_name = param.attrib.get('name')
            arg_sub = param.attrib.get('rename')
            if arg_name and arg_sub:
                args = [ x for x in self.args if x[1] == arg_name]
                for arg in args:
                    arg[2]['original-name'] = arg[1]
                    arg[1] = arg_sub


class DocString:
    orig_docstring = None
    parameters = None
    return_value = None
    description = None

    def __init__(self, function, docstring, binding_data):
        self.binding_data = binding_data
        self.orig_docstring = docstring
        self.parameters = []
        self.params = {}
        lines = docstring.splitlines()
        # ignore the first line, it has the symbol name
        lines = lines[1:]

        # look for parameters
        while lines[0].strip():
            if not self.parameters and not lines[0].startswith('@'):
                # function without parameters
                break
            if not self.parameters:
                self.parameters = []

            if lines[0][0] == '@':

                splits = lines[0][1:].split(':', 2)
                param_name = splits[0]
                if len(splits) > 2:
                    param_options = splits[1]
                    param_desc = splits[2]
                    self.parameters.append([param_name, param_desc, param_options])
                    self.params[param_name] = { 'desc': param_desc, 'options': param_options }
                    for a in function.args:
                        if a[1] == param_name or a[2].get('original-name') == param_name:
                            arg = a
                            break
                    else:
                        raise Exception('should not happen ' + param_name + ' ' + lines[0] + repr(function))
                    self.annotation2arg(arg, param_options)
                else:
                    param_desc = splits[1]
                    self.parameters.append([param_name, param_desc])
                    self.params[param_name] = { 'desc': param_desc }
            else:
                # continuation of previous description
                self.parameters[-1][1] = self.parameters[-1][1] + ' ' + lines[0].strip()

            lines = lines[1:]

        # blank line then description, till the end or the return value
        lines = lines[1:]
        self.description = ''
        while not lines[0].startswith('Return value'):
            self.description += lines[0] + '\n'
            if len(lines) == 1:
                self.description = self.description.strip()
                return
            lines = lines[1:]
        self.description = self.description.strip()

        # return value
        if lines[0].startswith('Return value') or lines[0].startswith('Returns'):
            lines[0] = lines[0].split(':', 1)[1]
            accu = ''
            while lines[0].strip():
                accu = accu + ' ' + lines[0].strip()
                if len(lines) == 1:
                    break
                lines = lines[1:]
            # find GObject-introspection annotations
            if re.match(r'\s*\(', accu):
                annotation, accu = accu.split(':', 1)
                self.annotation2arg(function.return_arg, annotation)
            self.return_value = accu.strip() # remove leading space
    def annotation2arg(self, arg, annotation):
        '''Convert GObject-introspection annotations to arg options'''

        if 'allow-none' in annotation:
            arg[2]['optional'] = True
        if re.search(r'\(\s*out\s*\)', annotation):
            arg[2]['out'] = True
        if re.search(r'\(\s*in\s*\)', annotation):
            arg[2]['in'] = True
        m = re.search(r'\(\s*default\s*([^ )]*)\s*\)', annotation)
        if m:
            prefix = ''
            if is_boolean(arg):
                prefix = 'b:'
            elif is_int(arg, self.binding_data):
                prefix = 'c:'
            else:
                raise Exception('should not happen: could not found type for default: ' + annotation)
            arg[2]['default'] = prefix + m.group(1)
            arg[2]['optional'] = True
        m = re.search(r'\(\s*element-type\s+(\w+)(?:\s+(\w+))?', annotation)
        if m:
            if len(m.groups()) > 2:
                arg[2]['key-type'] = \
                        convert_type_from_gobject_annotation(m.group(1))
                arg[2]['value-type'] = \
                        convert_type_from_gobject_annotation(m.group(2))
            else:
                arg[2]['element-type'] = \
                        convert_type_from_gobject_annotation(m.group(1))
        m = re.search(r'\(\s*transfer\s+(\w+)', annotation)
        if m:
            arg[2]['transfer'] = m.group(1)

def normalise_var(type, name):
    if name[0] == '*':
        type += '*'
        name = name[1:]
    return type, name

exclude_private = True

def parse_header(header_file):
    global binding

    struct_names = {}
    in_comment = False
    in_enum = False
    in_struct = None
    in_struct_private = False
    in_ifdef_zero = False

    lines = file(header_file).readlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        while line.endswith('\\\n'):
            i += 1
            line = line[:-2] + ' ' + lines[i].lstrip()

        if in_comment:
            if '*/' in line:
                in_comment = False
        elif '/*' in line and not '*/' in line:
            in_comment = True
        elif in_ifdef_zero:
            # minimal support for code sections commented with #if 0
            if line.startswith('#endif'):
                in_ifdef_zero = False
        elif line.startswith('#if 0'):
            in_ifdef_zero = True
        elif in_enum:
            if line.startswith('}'):
                in_enum = False
                enum_name = line[2:].strip().strip(';')
                binding.enums.append(enum_name)
            else:
                m = re.match('\s*([a-zA-Z0-9_]+)', line)
                if m:
                    binding.constants.append(('i', m.group(1)))
        elif line.startswith('#define'):
            m = re.match(r'#define\s+([a-zA-Z0-9_]+)\s+([-\w"]+)', line)
            if m:
                constant_name = m.group(1)
                if constant_name[0] != '_':
                    # ignore private constants
                    if '"' in line:
                        constant_type = 's'
                    elif m.group(2).startswith('LASSO_'):
                        l = [ c for c in binding.constants if m.group(2) == c[1] ]
                        if l:
                            contant_type = l[0][0]
                        else:
                            raise Exception()
                    else:
                        constant_type = 'i'
                    constant = (constant_type, constant_name)
                    binding.constants.append(constant)
        elif line.startswith('typedef enum {'):
            in_enum = True
        elif line.startswith('typedef struct'):
            m = re.match('typedef struct ([a-zA-Z0-9_]+)', line)
            if m:
                struct_name = m.group(1)
                if not (struct_name.endswith('Class') or struct_name.endswith('Private')):
                    struct_names[struct_name] = True
        elif line.startswith('struct _'):
            m = re.match('struct ([a-zA-Z0-9_]+)', line)
            struct_name = m.group(1)
            if struct_name in struct_names:
                in_struct = Struct(struct_name)
                in_struct_private = False
        elif in_struct:
            if line.startswith('}'):
                if not in_struct.name in binding.structs_toskip:
                    binding.structs.append(in_struct)
                else:
                    print >>sys.stderr, 'W: skipping structure %s due to overrides.xml' % in_struct.name
                in_struct = None
            elif '/*< public >*/' in line:
                in_struct_private = False
            elif '/*< private >*/' in line:
                in_struct_private = True
            elif in_struct_private and exclude_private:
                pass
            elif 'DEPRECATED' in line and exclude_private:
                pass
            else:
                # TODO: Add parsing of OFTYPE
                # Transform struct to typedef
                # example: "struct _LassoAssertion" -> "LassoAssertion"
                line = re.sub('\s+struct _', ' ', line)
                member_match = re.match('\s+(\w+)\s+(\*?\w+)', line)
                if member_match:
                    member_type, member_name = normalise_var(member_match.group(1), member_match.group(2))
                    field = (member_type, member_name, {})
                    if member_type == 'void*':
                        print >>sys.stderr, 'W: skipping field %s.%s' % (in_struct.name, member_name)
                    else:
                        if is_glist(field) or is_hashtable(field):
                            found = re.search(r' of ([^*]*)', line)
                            if found:
                                field[2]['element-type'] = clean_type(found.group(1))
                        if member_name == 'parent':
                            in_struct.parent = member_type
                        else:
                            in_struct.members.append(field) 
        elif line.startswith('LASSO_EXPORT '):
            while not line.strip().endswith(';'):
                i += 1
                line = line[:-1] + ' ' + lines[i].lstrip()

            # parse the type, then the name, then argument list
            m = re.match(r'LASSO_EXPORT\s+([^(]*(?:\s|\*))(\w+)\s*\(\s*(.*?)\s*\)\s*;', line)
            if m and (not exclude_private or not m.group(2).endswith('_get_type')):
                return_type, function_name, args = m.groups()
                return_type = return_type.strip()
                f = Function()
                if function_name[0] == '*':
                    return_type += '*'
                    function_name = function_name[1:]
                if binding.functions_toskip.get(function_name) != 1:
                    if re.search(r'\<const\>', return_type):
                        f.return_owner = False
                    # clean the type
                    return_type = clean_type(return_type)
                    if return_type != 'void':
                        f.return_type = return_type
                        f.return_arg = (return_type, None, {})
                    if function_name.endswith('_destroy') and exclude_private:
                        # skip the _destroy functions, they are just wrapper over
                        # g_object_unref
                        pass
                    else:
                        f.name = function_name
                        f.args = []
                        for arg in [x.strip() for x in args.split(',')]:
                            arg = clean_type(arg)
                            if arg == 'void' or arg == '':
                                continue
                            m = re.match(r'(.*(?:\s|\*))(\w+)', arg)
                            if m:
                                type, name = m.groups()
                                type = clean_type(type)
                                f.args.append(list((type, name, {})))
                            else:
                                print >>sys.stderr, 'failed to process:', arg, 'in line:', line
                                f.skip = True
                        f.apply_overrides()
                        if not f.skip:
                            binding.functions.append(f)
                        else:
                            print >>sys.stderr, 'W: skipping function', f

        i += 1


def parse_headers(srcdir):
    wsf_prefixes = ['disco_', 'dst_', 'is_', 'profile_service_', 'discovery_',
            'wsf_', 'interaction_', 'utility_', 'sa_', 'authentication_',
            'wsse_', 'sec_', 'idwsf2_', 'wsf2_', 'wsa_', 'wsu', 'soap_binding']

    srcdir = os.path.abspath(srcdir)
    parentdir = os.path.dirname(srcdir)

    exclusion = ('xml_idff.h', 'xml_idwsf.h', 'xml_saml2.h', \
            'xml_idwsf2.h', 'xml_soap11.h',
            'lasso_config.h', 'saml2_xsd.h' )
    if not binding.options.idwsf:
        exclusion += ( 'idwsf_strings.h', )
    for base, dirnames, filenames in os.walk(srcdir):
        bname = os.path.basename(base)
        if bname == '.svn':
            # ignore svn directories
            continue
        if not 'Makefile.am' in filenames:
            # not a source dir
            continue
        if not binding.options.idwsf and (bname == 'id-wsf' or \
                bname == 'id-wsf-2.0' or bname == 'ws'):
            # ignore ID-WSF
            continue
        makefile_am = open(os.path.join(base, 'Makefile.am')).read()
        filenames = [x for x in filenames if x.endswith('.h') if x in makefile_am]
        for filename in filenames:
            if filename in exclusion:
                continue
            if 'private' in filename:
                continue
            if not binding.options.idwsf:
                if True in (filename.startswith(wsf_prefix) for wsf_prefix in wsf_prefixes):
                    continue
            header_path = os.path.join(base, filename)
            header_relpath = os.path.relpath(header_path, parentdir)

            binding.headers.append(header_relpath)
            parse_header(header_path)
    binding.constants.append(('b', 'LASSO_WSF_ENABLED'))

def main():
    global binding

    parser = OptionParser()
    parser.add_option('-l', '--language', dest = 'language')
    parser.add_option('-s', '--src-dir', dest = 'srcdir', default = '../lasso/')
    parser.add_option('--enable-id-wsf', dest = 'idwsf', action = 'store_true')
    parser.add_option('--enable-exception-docs', dest= 'exception_doc', action = 'store_true')

    options, args = parser.parse_args()
    if not options.language:
        parser.print_help()
        sys.exit(1)

    binding = BindingData(options)
    parse_headers(options.srcdir)
    binding.look_for_docstrings(options.srcdir, options.exception_doc)
    binding.order_class_hierarchy()
    binding.attach_methods()

    if options.language == 'python':
        from python import lang

        python_binding = lang.Binding(binding)
        python_binding.generate()
    elif options.language == 'php5':
        from php5 import lang

        php5_binding = lang.Binding(binding)
        php5_binding.generate()
    elif options.language == 'java':
        from java import lang

        java_binding = lang.Binding(binding)
        java_binding.generate()
    elif options.language == 'java-list':
        from java import lang

        java_binding = lang.Binding(binding)
        java_binding.print_list_of_files()
    elif options.language == 'perl':
        from perl import lang
        perl_binding = lang.Binding(binding)
        perl_binding.generate()

if __name__ == '__main__':
    main()

