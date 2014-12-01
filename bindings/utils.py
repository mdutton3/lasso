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

import re
import string

_mapping_convert_type_from_gobject_annotation = {
        'utf8': 'char*'
}

def convert_type_from_gobject_annotation(type):
    return _mapping_convert_type_from_gobject_annotation.get(type, type)

def clean_type(type):
    '''Convert struct references to their typedef counterpart'''
    if not type:
        return type
    type = type.strip()
    type = re.sub('\s+', ' ', type)
    m = re.match('\s*struct\s+_(\w+)\s*\*', type)
    if m:
        type = '%s*' % m.group(1)
    return re.sub('\s*\*\s*', '*', type)


def camelcase_to_list(varname):
    ''' convert 'camlCaseISTheThing' to ['caml', 'Case', 'IS', 'The', 'Thing']'''
    l = [[]]
    last = None
    for x in varname:
        if last:
            if last.isupper() and x.isupper():
                pass
            elif not last.isupper() and x.isupper():
                l.append([])
            elif last.isupper() and x.islower():
                y = l[-1][-1]
                del l[-1][-1]
                if not l[-1]:
                    del l[-1]
                l.append([y])
            l[-1].append(x)
        else:
            l[-1].append(x)
        last = x
    return list(map(str.lower,map(''.join,l)))

def old_format_as_camelcase(var):
    '''Format an identifier name into CamelCase'''
    if '_' in var:
        return format_underscore_as_camelcase(var)
    if var[0] in string.ascii_uppercase:
        var = var[0].lower() + var[1:]
    var = re.sub(r'([a-z])(ID)([A-Z]|$)', r'\1Id\3', var) # replace standing ID by Id
    return var

def format_as_camelcase(var):
    '''Format an identifier name into CamelCase'''
    if var[0].isupper():
        l = camelcase_to_list(var)
        return l[0] + ''.join(list(map(str.capitalize, l[1:])))
    if '_' in var:
        return format_underscore_as_camelcase(var)
    if var[0] in string.ascii_uppercase:
        var = var[0].lower() + var[1:]
    var = re.sub(r'([a-z])(ID)([A-Z]|$)', r'\1Id\3', var) # replace standing ID by Id
    return var

def format_as_underscored(var):
    '''Format an identifier name into underscored_name'''
    var = '_'.join(camelcase_to_list(var))
    var = var.replace('id_wsf2_', 'idwsf2_')
    var = var.replace('_saslresponse', '_sasl_response')
    var = var.replace('ws_addr_', 'wsa_')
    return var

def format_underscore_as_camelcase(var):
    '''Format an underscored identifier name into CamelCase'''
    def rep(s):
        return s.group(1)[0].upper() + s.group(1)[1:]
    var = re.sub(r'_([A-Za-z0-9]+)', rep, var)
    var = re.sub(r'([a-z])(ID)([A-Z]|$)', r'\1Id\3', var) # replace standing ID by Id
    return var



def last(x):
    return x[len(x)-1]

def common_prefix(x,y):
    max = min(len(x),len(y))
    last = 0
    for i in range(max):
        if x[i] != y[i]:
            return min(i,last+1)
        if x[i] == '_':
            last = i
    return max

def pgroup(group,prev):
    level, l = group
    i = 0
    for x in l:
        if i == 0:
            prefix = prev
        else:
            prefix = level
        if isinstance(x,tuple):
            pgroup(x,prefix)
        else:
            print(prefix * ' ' + x[prefix:])
        i = i + 1

def group(list):
    list.sort()
    pile = [(0,[])]
    prev = ""
    for x in list:
        l, g = last(pile)
        u = common_prefix(x,prev)
        # Find the good level of insertion
        while u < l:
            pile.pop()
            l, g = last(pile)
        # Insert here
        if u == l:
            g.append(x)
        elif u > l:
            t = (u, [g.pop(),x])
            g.append(t)
            pile.append(t)
        prev = x
    return pile[0]

def _test_arg(arg, what):
    if isinstance(arg, tuple) or isinstance(arg, list):
        return bool(arg[2].get(what))
    return False

def is_optional(arg):
    return _test_arg(arg, 'optional')

def element_type(arg):
    return arg[2].get('element-type')

def key_type(arg):
    return arg[2].get('key-type')

def value_type(arg):
    return arg[2].get('value-type')

def is_out(arg):
    return _test_arg(arg, 'out') or (arg_type(arg).endswith('**') and not _test_arg(arg, 'in'))


def is_glist(arg):
    return re.match('GList', unconstify(var_type(arg)))

def is_hashtable(arg):
    return re.match('GHashTable', unconstify(var_type(arg)))

def var_type(arg):
    '''Return the type of variable to store content'''
    arg = arg_type(arg)
    if is_out(arg):
        return arg[:-1]
    else:
        return arg

def unref_type(arg):
    return (var_type(arg), arg[1], arg[2])

def ref_name(arg):
    if is_out(arg):
        return '&%s' % arg[1]
    else:
        return arg[1]

def arg_type(arg):
    if isinstance(arg, tuple) or isinstance(arg, list):
        return arg[0]
    else:
        return arg

def arg_name(arg):
    return arg[1]

def unconstify(type):
    type = arg_type(type)
    if isinstance(type, str):
        return re.sub(r'\bconst\b\s*', '', type).strip()
    else:
        return type

def make_arg(type):
    return (type,'',{})

def arg_default(arg):
    return arg[2].get('default')

def remove_modifiers(type):
    if isinstance(type, str):
        type = re.sub(r'\s*\bunsigned\b\s*', ' ', type).strip()
        type = re.sub(r'\s*\bconst\b\s*', ' ', type).strip()
        type = re.sub(r'\s*\bsigned\b\s*', ' ', type).strip()
        type = re.sub(r'\s*\bvolatile\b\s*', ' ', type).strip()
        return clean_type(type)
    else:
        return type

def is_const(arg):
    return bool(re.search(r'\bconst\b', arg_type(arg)))

def is_cstring(arg):
    arg = arg_type(arg)
    return clean_type(unconstify(arg)) in ('char*','gchar*','guchar*','string','utf8','strings')

def is_xml_node(arg):
    arg = unconstify(arg_type(arg))
    return arg and arg.startswith('xmlNode')

def is_boolean(arg):
    return arg_type(arg) in ('gboolean','bool')

def is_pointer(arg):
    return arg_type(arg).endswith('*')

def unpointerize(arg):
    return arg_type(arg).replace('*','')

def is_list(arg):
    return unconstify(arg_type(arg)).startswith('GList')

def is_rc(arg):
    return arg_type(arg) in [ 'lasso_error_t' ]

def is_int(arg, binding_data):
    return remove_modifiers(arg_type(arg)) in [ 'time_t', 'int', 'gint', 'long', 'glong', 'lasso_error_t'] + binding_data.enums

def is_time_t_pointer(arg):
    return re.match(r'\btime_t\*', unconstify(arg_type(arg)))

def is_transfer_full(arg, default=False):
    if not isinstance(arg, tuple):
        return default
    transfer = arg[2].get('transfer')
    if transfer:
        return transfer == 'full'
    if is_cstring(arg) and is_const(arg):
        return False
    return default or is_out(arg) or is_object(arg)

_not_objects = ( 'GHashTable', 'GList', 'GType' )

def is_object(arg):
    t = clean_type(unconstify(arg_type(arg)))
    return t and t[0] in string.ascii_uppercase and not [ x for x in _not_objects if x in t ]

if __name__ == '__main__':
    print(camelcase_to_list('Samlp2IDPList'))
