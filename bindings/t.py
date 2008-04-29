#! /usr/bin/env python

import os
import re

constants = []
structs = []
struct_names = {}

class Struct:
    def __init__(self, name):
        self.name = name
        self.parent = None
        self.members = []

    def __repr__(self):
        return '<Struct name:%s, childof:%s>' % (self.name, self.parent)


def parse(header_file):
    in_comment = False
    in_enum = False
    in_struct = None
    in_struct_private = False

    lines = file(header_file).readlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.endswith('\\\n'):
            i += 1
            line = line[:-2] + ' ' + lines[i]

        if in_comment:
            if '*/' in line:
                in_comment = False
        elif '/*' in line and not '*/' in line:
            in_comment = True
        elif in_enum:
            if line.startswith('}'):
                in_enum = False
            else:
                m = re.match('\s*([a-zA-Z0-9_]+)', line)
                if m:
                    constants.append(m.group(1))
        elif line.startswith('#define'):
            m = re.match(r'#define\s+([a-zA-Z0-9_]+)\s+[-\w"]', line)
            if m:
                constant = m.group(1)
                if constant[0] != '_':
                    # ignore private constants
                    constants.append(constant)
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
                structs.append(in_struct)
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
                        in_struct.members.append((member_type, member_name))

        i += 1


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
        parse(os.path.join(base, filename))


def display_structs():
    for struct in structs:
        print struct
        for m in struct.members:
            print '  ', m

import pprint
pprint.pprint(constants)
display_structs()
