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

    content = file(header_file).read().replace('\\\n', ' ')
    for line in content.splitlines():
        if in_comment:
            if '*/' in line:
                in_comment = False
            continue

        if '/*' in line and not '*/' in line:
            in_comment = True
            continue

        if in_enum:
            if line.startswith('}'):
                in_enum = False
            else:
                m = re.match('\s*([a-zA-Z0-9_]+)', line)
                if m:
                    constants.append(m.group(1))
                continue

        if line.startswith('#define'):
            m = re.match(r'#define\s+([a-zA-Z0-9_]+)\s+[-\w"]', line)
            if not m:
                continue
            constant = m.group(1)
            if constant[0] == '_':
                # ignore private constants
                continue
            constants.append(constant)
            continue

        if line.startswith('typedef enum {'):
            in_enum = True
            continue

        if line.startswith('typedef struct'):
            m = re.match('typedef struct ([a-zA-Z0-9_]+)', line)
            if not m:
                continue
            struct_name = m.group(1)
            if struct_name.endswith('Class') or struct_name.endswith('Private'):
                continue
            struct_names[struct_name] = True
            continue

        if line.startswith('struct _'):
            m = re.match('struct ([a-zA-Z0-9_]+)', line)
            struct_name = m.group(1)
            if not struct_name in struct_names:
                continue
            in_struct = Struct(struct_name)
            in_struct_private = False
            continue

        if in_struct:
            if line.startswith('}'):
                structs.append(in_struct)
                in_struct = None
                continue

            if '/*< public >*/' in line:
                in_struct_private = False
                continue

            if '/*< private >*/' in line:
                in_struct_private = True
                continue

            if in_struct_private:
                continue

            member_match = re.match('\s+(\w+)\s+(\*?\w+)', line)
            if member_match:
                member_type = member_match.group(1)
                member_name = member_match.group(2)
                if member_name == 'parent':
                    in_struct.parent = member_type
                else:
                    in_struct.members.append((member_type, member_name))
                continue

            continue



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
