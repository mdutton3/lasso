#! /usr/bin/env python

import os
import re

constants = []
structs = []
struct_names = {}

class Struct:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Struct name:%s>' % self.name


def parse(header_file):
    in_comment = False
    in_enum = False
    in_struct = None

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
            continue

        if in_struct:
            if line.startswith('}'):
                structs.append(in_struct)
                in_struct = None
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


import pprint
pprint.pprint(structs)

