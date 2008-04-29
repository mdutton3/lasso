#! /usr/bin/env python

import os
import re

import lang_python

class BindingData:
    def __init__(self):
        self.headers = []
        self.constants = []
        self.structs = []
        self.struct_dict = {}
        self.functions = []
        self.enums = []

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
    
    def __repr__(self):
        return '%s %s %r' % (self.return_type, self.name, self.args)


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
        elif in_enum:
            if line.startswith('}'):
                in_enum = False
                enum_name = line[2:].strip().strip(';')
                binding.enums.append(enum_name)
            else:
                m = re.match('\s*([a-zA-Z0-9_]+)', line)
                if m:
                    binding.constants.append(m.group(1))
        elif line.startswith('#define'):
            m = re.match(r'#define\s+([a-zA-Z0-9_]+)\s+[-\w"]', line)
            if m:
                constant = m.group(1)
                if constant[0] != '_':
                    # ignore private constants
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
                        in_struct.members.append(normalise_var(member_type, member_name))
        elif line.startswith('LASSO_EXPORT '):
            while not line.strip().endswith(';'):
                i += 1
                line = line[:-1] + lines[i].lstrip()

            m = re.match(r'LASSO_EXPORT\s+([\w]+\*?)\s+(\*?\w+)\s*\((.*?)\)', line)
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
                        f.args.append(normalise_var(m.group(1), m.group(3)))
                    else:
                        print 'failed to process:', arg, 'in line:', line

        i += 1


def parse_headers():
    for base, dirnames, filenames in os.walk('../lasso/'):
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


binding = BindingData()
parse_headers()
binding.order_class_hierarchy()
binding.attach_methods()

python_binding = lang_python.PythonBinding(binding)
python_binding.generate()

import pprint
#binding.display_structs()
#binding.display_funcs()
