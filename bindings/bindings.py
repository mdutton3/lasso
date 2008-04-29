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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import os
import re
import sys

from optparse import OptionParser
import elementtree.ElementTree as ET

class BindingData:
    def __init__(self):
        self.headers = []
        self.constants = []
        self.structs = []
        self.struct_dict = {}
        self.functions = []
        self.enums = []
        self.overrides = ET.parse('overrides.xml')

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
            if f.name.endswith('_new'):
                # constructor for another class
                continue
            arg_type = f.args[0][0]
            if arg_type[-1] == '*':
                arg_type = arg_type[:-1]
            c = self.struct_dict.get(arg_type)
            if not c:
                continue
            c.methods.append(f)
            self.functions.remove(f)

    def look_for_docstrings(self, srcdir):
        regex = re.compile(r'\/\*\*\s(.*?)\*\*\/', re.DOTALL)
        for base, dirnames, filenames in os.walk(srcdir):
            if base.endswith('/.svn'):
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
                    func = [f for f in self.functions if f.name == function_name]
                    if not func:
                        continue
                    func = func[0]
                    func.docstring = docstring



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


class Function:
    return_type = None
    name = None
    args = None
    docstring = None
    
    def __repr__(self):
        return '%s %s %r' % (self.return_type, self.name, self.args)

    def apply_overrides(self):
        for func in binding.overrides.findall('func'):
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


def normalise_var(type, name):
    if name[0] == '*':
        type += '*'
        name = name[1:]
    return type, name


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
            m = re.match(r'#define\s+([a-zA-Z0-9_]+)\s+[-\w"]', line)
            if m:
                constant = m.group(1)
                if constant[0] != '_':
                    # ignore private constants
                    if '"' in line:
                        constant_type = 's'
                    else:
                        constant_type = 'i'
                    binding.constants.append((constant_type, constant))
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
                binding.structs.append(in_struct)
                in_struct = None
            elif '/*< public >*/' in line:
                in_struct_private = False
            elif '/*< private >*/' in line:
                in_struct_private = True
            elif in_struct_private:
                pass
            else:
                member_match = re.match('\s+(\w+)\s+(\*?\w+)', line)
                if member_match:
                    member_type = member_match.group(1)
                    member_name = member_match.group(2)
                    if member_name == 'parent':
                        in_struct.parent = member_type
                    else:
                        in_struct.members.append(
                                list(normalise_var(member_type, member_name)) + [{}])
                    if member_type == 'GList':
                        options = in_struct.members[-1][-1]
                        if '/* of' in line:
                            of_type = line[line.index('/* of')+6:].split()[0]
                            if of_type == 'strings':
                                of_type = 'char*'
                            options['elem_type'] = of_type
        elif line.startswith('LASSO_EXPORT '):
            while not line.strip().endswith(';'):
                i += 1
                line = line[:-1] + lines[i].lstrip()

            m = re.match(r'LASSO_EXPORT\s+((?:const |)[\w]+\*?)\s+(\*?\w+)\s*\((.*?)\)', line)
            if m and not m.group(2).endswith('_get_type'):
                f = Function()
                binding.functions.append(f)
                return_type, function_name, args = m.groups()
                if function_name[0] == '*':
                    return_type += '*'
                    function_name = function_name[1:]
                if return_type != 'void':
                    f.return_type = return_type
                f.name = function_name
                f.args = []
                for arg in [x.strip() for x in args.split(',')]:
                    if arg == 'void' or arg == '':
                        continue
                    m = re.match(r'((const\s+)?\w+\*?)\s+(\*?\w+)', arg)
                    if m:
                        f.args.append(list(normalise_var(m.group(1), m.group(3))) + [{}])
                    else:
                        print 'failed to process:', arg, 'in line:', line
                f.apply_overrides()

        i += 1


def parse_headers(srcdir):
    for base, dirnames, filenames in os.walk(srcdir):
        if base.endswith('/.svn'):
            # ignore svn directories
            continue
        if not 'Makefile.am' in filenames:
            # not a source dir
            continue
        makefile_am = open(os.path.join(base, 'Makefile.am')).read()
        filenames = [x for x in filenames if x.endswith('.h') if x in makefile_am]
        for filename in filenames:
            if filename == 'lasso_config.h' or 'private' in filename:
                continue
            binding.headers.append(os.path.join(base, filename)[3:])
            parse_header(os.path.join(base, filename))
        binding.headers.insert(0, 'lasso/xml/saml-2.0/saml2_assertion.h')


def main():
    global binding

    parser = OptionParser()
    parser.add_option('-l', '--language', dest = 'language')
    parser.add_option('-s', '--src-dir', dest = 'srcdir', default = '../lasso/')

    options, args = parser.parse_args()
    if not options.language:
        parser.print_help()
        sys.exit(1)

    binding = BindingData()
    parse_headers(options.srcdir)
    binding.look_for_docstrings(options.srcdir)
    binding.order_class_hierarchy()
    binding.attach_methods()

    if options.language == 'python':
        import lang_python

        python_binding = lang_python.PythonBinding(binding)
        python_binding.generate()


if __name__ == '__main__':
    main()

