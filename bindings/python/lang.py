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
from six import print_
import sys
import re
import textwrap
from utils import *


def remove_bad_optional(args):
    args.reverse()
    non_opt = False
    new_args = []
    for x in args:
        if not '=' in x:
            non_opt = True
        elif non_opt:
            print_('W: changed', x, file=sys.stderr)
            x = re.sub(' *=.*', '', x)
            print_('to', x, file=sys.stderr)
        new_args.append(x)
    new_args.reverse()
    return new_args

def defval_to_python_value(defval):
    if defval is None:
        return 'None'
    if defval.startswith('b:'):
        if defval[2:].lower() == 'true':
            return 'True'
        if defval[2:].lower() == 'false':
            return 'False'
    if defval.startswith('c:'):
        try:
            return str(int(defval[2:]))
        except:
            return defval[8:]
    raise Exception('Could not convert %s to python value' % defval)

def get_python_arg_decl(arg):
    if is_optional(arg):
        return '%s = %s' % (arg_name(arg), defval_to_python_value(arg_default(arg)))
    else:
        return arg_name(arg)

class Binding:
    def __init__(self, binding_data):
        self.binding_data = binding_data
        self.src_dir = os.path.dirname(__file__)

    def free_value(self, fd, type, name = None):
        if not name:
            name = arg_name(type)
        if not name:
            raise Exception('Cannot free, missing a name')
        if is_cstring(type):
            print_('    lasso_release_string(%s);' % name, file=fd)
        elif is_int(type, self.binding_data) or is_boolean(type):
            pass
        elif is_xml_node(type):
            print_('    lasso_release_xml_node(%s);' % name, file=fd)
        elif is_glist(type):
            etype = element_type(type)
            if is_cstring(etype):
                print_('    lasso_release_list_of_strings(%s);' % name, file=fd)
            elif is_object(etype):
                print_('    lasso_release_list_of_gobjects(%s);' % name, file=fd)
            else:
                raise Exception('Unsupported caller owned return type %s' % ((repr(type), name),))
        elif is_hashtable(type):
            raise Exception('Unsupported caller owned return type %s' % ((repr(type), name),))
        elif is_object(type):
            print_('    if (return_value) g_object_unref(%s);' % name, file=fd)
        else:
            raise Exception('Unsupported caller owned return type %s' % ((repr(type), name),))


    def generate(self):
        fd = open('lasso.py', 'w')
        self.generate_header(fd)
        self.generate_exceptions(fd)
        self.generate_constants(fd)
        for clss in self.binding_data.structs:
            self.generate_class(clss, fd)
        self.generate_functions(fd)
        self.generate_footer(fd)
        fd.close()

        fd = open('_lasso.c', 'w')
        self.generate_wrapper(fd)
        fd.close()

    def generate_header(self, fd):
        print_('''\
# this file has been generated automatically; do not edit

import _lasso
import sys


def cptrToPy(cptr):
    if cptr is None:
        return None
    klass = getattr(lasso, cptr.typename)
    o = klass.__new__(klass)
    o._cptr = cptr
    return o

if sys.version_info >= (3,):
    def str2lasso(s):
        return s
else: # Python 2.x
    def str2lasso(s):
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return s

class frozendict(dict):
    \'\'\'Immutable dict\'\'\'
    # from Python Cookbook:
    #   http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/414283
    def _blocked_attribute(obj):
        raise AttributeError('A frozendict cannot be modified.')
    _blocked_attribute = property(_blocked_attribute)

    __delitem__ = __setitem__ = clear = _blocked_attribute
    pop = popitem = setdefault = update = _blocked_attribute

    def __new__(cls, *args):
        new = dict.__new__(cls)
        dict.__init__(new, *args)
        return new

    def __init__(self, *args):
        pass

    def __hash__(self):
        try:
            return self._cached_hash
        except AttributeError:
            h = self._cached_hash = hash(tuple(sorted(self.items())))
            return h

    def __repr__(self):
        return 'frozendict(%s)' % dict.__repr__(self)
''', file=fd)

    def generate_exceptions(self, fd):
        done_cats = []
        print_('''\
class Error(Exception):
    code = None

    @staticmethod
    def raise_on_rc(rc):
        global exceptions_dict
        if rc != 0:
            exception = exceptions_dict.get(rc, Error())
            exception.code = rc
            raise exception

    def __str__(self):
        if self.code:
            return '<lasso.%s(%s): %s>' % (self.__class__.__name__, self.code, _lasso.strError(self.code))
        else:
            return '<lasso.%s: %s>' % (self.__class__.__name__, self.message)

    def __getitem__(self, i):
        # compatibility with SWIG bindings
        if i == 0:
            return self.code
        elif i == 1:
            return _lasso.strError(self.code)
        else:
            raise IndexError()
''', file=fd)
        for exc_cat in self.binding_data.overrides.findall('exception/category'):
            cat = exc_cat.attrib.get('name')
            done_cats.append(cat)
            parent_cat = exc_cat.attrib.get('parent', '')
            print_('''\
class %sError(%sError):
    pass
''' % (cat, parent_cat), file=fd)

        exceptions_dict = {}

        for c in self.binding_data.constants:
            m = re.match(r'LASSO_(\w+)_ERROR_(.*)', c[1])
            if not m:
                continue
            cat, detail = m.groups()
            cat = cat.title().replace('_', '')
            detail = (cat + '_' + detail).title().replace('_', '')
            if not cat in done_cats:
                done_cats.append(cat)
                for exc_cat in self.binding_data.overrides.findall('exception/category'):
                    if exc_cat.attrib.get('name') == cat:
                        parent_cat = exc_cat.attrib.get('parent')
                        break
                else:
                    parent_cat = ''

                print_('''\
class %sError(%sError):
    pass
''' % (cat, parent_cat), file=fd)

            exceptions_dict[detail] = c[1][6:]

            if (detail, cat) == ('UnsupportedProfile', 'Logout'):
                # skip Logout/UnsupportedProfile exception as its name would
                # be the same as Profile/UnsupportedProfile; it is not a
                # problem skipping it as they both inherit from ProfileError
                # and the exception code will correctly be set by raise_on_rc
                # afterwards.  (actually it is even totally unnecessary to skip
                # it here as Profile/UnsupportedProfile is handled after
                # Logout/UnsupportedProfile, this is just done in the case the
                # ordering would change)
                continue

            print_('''\
class %sError(%sError):
    pass
''' % (detail, cat), file=fd)

        print_('exceptions_dict = {', file=fd)
        for k, v in exceptions_dict.items():
            print_('    _lasso.%s: %sError,' % (v, k), file=fd)
        print_('}', file=fd)
        print_('', file=fd)

    def generate_footer(self, fd):
        print_('''

import lasso

# backward compatibility with the SWIG binding

WSF_SUPPORT = WSF_ENABLED

Profile.isIdentityDirty = property(Profile.hasDirtyIdentity)
Profile.isSessionDirty = property(Profile.hasDirtySession)

def identity_get_provider_ids(self):
    return self.federations.keys()
Identity.providerIds = property(identity_get_provider_ids)

def server_get_provider_ids(self):
    return self.providers.keys()
Server.providerIds = property(server_get_provider_ids)

def session_get_provider_ids(self):
    return self.assertions.keys()
Session.providerIds = property(session_get_provider_ids)

def LassoNode__getstate__(self):
    return { '__dump__': self.dump() }

def LassoNode__setstate__(self, d):
    self._cptr = _lasso.node_new_from_dump(d.pop('__dump__'))

Node.__getstate__ = LassoNode__getstate__
Node.__setstate__ = LassoNode__setstate__

Samlp2AuthnRequest.nameIDPolicy = Samlp2AuthnRequest.nameIdPolicy
LibAuthnRequest.nameIDPolicy = LibAuthnRequest.nameIdPolicy
Saml2Subject.nameID = Saml2Subject.nameId
MiscTextNode.text_child = MiscTextNode.textChild
NodeList = list
StringList = list
StringDict = dict
registerIdWsf2DstService = registerIdwsf2DstService

if WSF_SUPPORT:
    DiscoDescription_newWithBriefSoapHttpDescription = DiscoDescription.newWithBriefSoapHttpDescription
    Discovery.buildRequestMsg = Discovery.buildSoapRequestMsg
    InteractionProfileService.buildRequestMsg = InteractionProfileService.buildSoapRequestMsg
    InteractionProfileService.buildResponseMsg = InteractionProfileService.buildSoapResponseMsg
    DataService.buildRequestMsg = DataService.buildSoapRequestMsg
    DiscoModifyResponse.newEntryIds = DiscoModifyResponse.newEntryIDs
''', file=fd)

    def generate_constants(self, fd):
        print_('### Constants (both enums and defines)', file=fd)
        for c in self.binding_data.constants:
            print_('%s = _lasso.%s' % (c[1][6:], c[1][6:]), file=fd)
        for c in self.binding_data.overrides.findall('constant'):
            name = c.attrib.get('name')
            if c.attrib.get('value'):
                name = name[6:] # dropping LASSO_
                value = c.attrib.get('value')
                if value == 'True':
                    print_('%s = True' % name, file=fd)
                else:
                    print_('E: unknown value for constant: %r' % value, file=sys.stderr)
        print_('', file=fd)

    def generate_class(self, clss, fd):
        klassname = clss.name[5:] # remove Lasso from class name
        if clss.parent == 'GObject':
            parentname = 'object'
        else:
            parentname = clss.parent[5:]

        print_('''class %(klassname)s(%(parentname)s):''' % locals(), file=fd)

        methods = clss.methods[:]
        # constructor(s)
        method_prefix = 'lasso_' + format_as_underscored(klassname) + '_'
        empty = True
        for m in self.binding_data.functions:
            if m.name == method_prefix + 'new':
                empty = False
                c_args = []
                py_args = []
                for arg in m.args:
                    py_args.append(get_python_arg_decl(arg))
                    if not is_int(arg, self.binding_data) and is_object(arg):
                        c_args.append('%(name)s and %(name)s._cptr' % { 'name' : arg_name(arg) })
                    elif is_cstring(arg):
                        c_args.append('str2lasso(%s)' % arg_name(arg))
                    else:
                        c_args.append(arg_name(arg))
                py_args = remove_bad_optional(py_args)

                c_args = ', '.join(c_args)
                py_args = ', ' + ', '.join(py_args)
                print_('    def __init__(self%s):' % py_args, file=fd)
                # XXX: could check self._cptr.typename to see if it got the
                # right class type
                print_('        self._cptr = _lasso.%s(%s)' % (
                        m.name[6:], c_args), file=fd)
                print_('        if self._cptr is None:', file=fd)
                print_('            raise Error(\'failed to create object\')', file=fd)
                print_('', file=fd)

        for m in self.binding_data.functions:
            if m.name.startswith(method_prefix + 'new_'):
                empty = False
                constructor_name = format_as_camelcase(m.name[len(method_prefix):])
                c_args = []
                py_args = []
                for arg in m.args:
                    aname = arg_name(arg)
                    py_args.append(get_python_arg_decl(arg))

                    if not is_int(arg, self.binding_data) and is_object(arg):
                        c_args.append('%s and %s._cptr' % (aname, aname))
                    elif is_cstring(arg):
                        c_args.append('str2lasso(%s)' % arg_name(arg))
                    else:
                        c_args.append(aname)
                opt = False
                py_args = remove_bad_optional(py_args)
                for x in py_args:
                    if '=' in x:
                        opt = True
                    elif opt:
                        print_('W: non-optional follows optional,', m, file=sys.stderr)
                c_args = ', '.join(c_args)
                py_args = ', ' + ', '.join(py_args)
                print_('    @classmethod', file=fd)
                print_('    def %s(cls%s):' % (constructor_name, py_args), file=fd)
                print_('         return cptrToPy(_lasso.%s(%s))' % (m.name[6:], c_args), file=fd)
                print_('', file=fd)

        # create properties for members
        for m in clss.members:
            empty = False
            mname = format_as_camelcase(m[1])
            options = m[2]
            # getter
            print_('    def get_%s(self):' % mname, file=fd)
            print_('        t = _lasso.%s_%s_get(self._cptr)' % (
                    klassname, mname), file=fd)
            if is_int(m, self.binding_data) or is_xml_node(m) or is_cstring(m) or is_boolean(m):
                pass
            elif is_object(m):
                print_('        t = cptrToPy(t)', file=fd)
            elif is_glist(m):
                el_type = element_type(m)
                if is_cstring(el_type):
                    pass
                elif is_xml_node(el_type):
                    pass
                elif is_object(el_type):
                    print_('        if not t: return t', file=fd)
                    print_('        t = tuple([cptrToPy(x) for x in t])', file=fd)
                else:
                    raise Exception('Unsupported python getter %s.%s' % (clss, m))
            elif is_hashtable(m):
                el_type = element_type(m)
                print_('        if not t: return t', file=fd)
                if is_object(el_type):
                    print_('        d2 = {}', file=fd)
                    print_('        for k, v in t.items():', file=fd)
                    print_('            d2[k] = cptrToPy(v)', file=fd)
                    print_('        t = frozendict(d2)', file=fd)
                else:
                    print_('        t = frozendict(t)', file=fd)
            elif is_boolean(m) or is_int(m, self.binding_data) or is_xml_node(m) or is_cstring(m):
                pass
            else:
                raise Exception('Unsupported python getter %s.%s' % (clss, m))
            print_('        return t;', file=fd)
            # setter
            print_('    def set_%s(self, value):' % mname, file=fd)
            if is_int(m, self.binding_data) or is_xml_node(m) or is_boolean(m):
                pass
            elif is_cstring(m):
                print_('        value = str2lasso(value)', file=fd)
            elif is_object(m):
                print_('        if value is not None:', file=fd)
                print_('            value = value and value._cptr', file=fd)
            elif is_glist(m):
                el_type = element_type(m)
                if is_cstring(el_type) or is_xml_node(el_type):
                    pass
                elif is_object(el_type):
                    print_('        if value is not None:', file=fd)
                    print_('            value = tuple([x._cptr for x in value])', file=fd)
                else:
                    raise Exception('Unsupported python setter %s.%s' % (clss, m))
            elif is_hashtable(m):
                print_('W: unsupported setter for hashtable %s' % (m,), file=sys.stderr)
            else:
                print_('W: unsupported setter for %s' % (m,), file=sys.stderr)
            print_('        _lasso.%s_%s_set(self._cptr, value)' % (
                    klassname, mname), file=fd)
            print_('    %s = property(get_%s, set_%s)' % (mname, mname, mname), file=fd)
            old_mname = old_format_as_camelcase(m[1])
            if mname != old_mname:
                print_('    %s = %s' % (old_mname, mname), file=fd)
            print_('', file=fd)

        # first pass on methods, getting accessors
        # second pass on methods, real methods
        for m in methods:
            empty = False
            if m.name.endswith('_new') or m.name.endswith('_new_from_dump') or \
                    m.name.endswith('_new_full'):
                continue
            if not m.name.startswith(method_prefix):
                print_('W:', m.name, 'vs', method_prefix, file=sys.stderr)
                continue

            if m.rename:
                mname = m.rename[len(method_prefix):]
                function_name = m.rename[6:]
            else:
                mname = m.name[len(method_prefix):]
                function_name = m.name[6:]
            py_args = []
            c_args = []
            outarg = None
            for arg in m.args[1:]:
                if is_out(arg):
                    assert not outarg
                    outarg = arg
                    outvar = '_%s_out' % arg_name(arg)
                else:
                    py_args.append(get_python_arg_decl(arg))

                if is_out(arg):
                    c_args.append(outvar)
                elif is_cstring(arg):
                    c_args.append('str2lasso(%s)' % arg_name(arg))
                elif is_xml_node(arg) or is_boolean(arg) or is_cstring(arg) or is_int(arg, self.binding_data) or is_glist(arg) or is_hashtable(arg) or is_time_t_pointer(arg):
                    c_args.append(arg_name(arg))
                elif is_object(arg):
                    c_args.append('%(name)s and %(name)s._cptr' % { 'name': arg_name(arg) })
                else:
                    raise Exception('Does not handle argument of type: %s' % ((m, arg),))
            # check py_args
            py_args = remove_bad_optional(py_args)
            opt = False
            for x in py_args:
                if '=' in x:
                    opt = True
                elif opt:
                    print_('W: non-optional follow optional,', m, file=sys.stderr)

            if py_args:
                py_args = ', ' + ', '.join(py_args)
            else:
                py_args = ''
            if c_args:
                c_args = ', ' + ', '.join(c_args)
            else:
                c_args = ''

            print_('    def %s(self%s):' % (
                    format_underscore_as_camelcase(mname), py_args), file=fd)
            if m.docstring:
                print_("        '''", file=fd)
                print_(self.format_docstring(m, mname, 8), file=fd)
                print_("        '''", file=fd)

            if outarg:
                print_("        %s = list((None,))" % outvar, file=fd)
            return_type = m.return_type
            return_type_qualifier = m.return_type_qualifier
            assert is_int(make_arg(return_type),self.binding_data) or not outarg
            if return_type in (None, 'void'):
                print_('        _lasso.%s(self._cptr%s)' % (
                        function_name, c_args), file=fd)
            elif is_rc(m.return_arg):
                print_('        rc = _lasso.%s(self._cptr%s)' % (
                        function_name, c_args), file=fd)
                print_('        Error.raise_on_rc(rc)', file=fd)
            elif is_int(m.return_arg, self.binding_data) or is_xml_node(m.return_arg) or is_cstring(m.return_arg) or is_boolean(m.return_arg):
                print_('        return _lasso.%s(self._cptr%s)' % (
                        function_name, c_args), file=fd)
            elif is_glist(m.return_arg):
                el_type = element_type(m.return_arg)
                if is_object(el_type):
                    print_('        value = _lasso.%s(self._cptr%s)' % (
                            function_name, c_args), file=fd)
                    print_('        if value is not None:', file=fd)
                    print_('            value = tuple([cptrToPy(x) for x in value])', file=fd)
                    print_('        return value', file=fd)
                elif is_cstring(el_type):
                    print_('        return _lasso.%s(self._cptr%s)' % (
                            function_name, c_args), file=fd)
                else:
                    raise Exception('Return Type GList<%s> is not supported' % el_type)
            elif is_hashtable(m.return_arg):
                raise Exception('Return type GHashTable unsupported')
            elif is_object(m.return_arg):
                print_('        return cptrToPy(_lasso.%s(self._cptr%s))' % (
                        function_name, c_args), file=fd)
            else:
                raise Exception('Return type %s is unsupported' % (m.return_arg,))
            if outarg:
                print_('        return %s[0]' % outvar, file=fd)
            print_('', file=fd)
        # transform methods to properties
        for m in methods:
            if len(m.args) > 1:
                continue
            name = m.rename or m.name
            suffix = name[len(method_prefix)+len('get_'):]
            if clss.getMember(suffix):
                print_('W: method %s and member %s clashes' % (m.name, arg_name(clss.getMember(suffix))), file=sys.stderr)
                continue
            if not name.startswith(method_prefix) or not name[len(method_prefix):].startswith('get_'):
                continue
            setter_suffix = 'set_' + suffix
            setter = None
            for n in methods:
                if n.name.endswith(setter_suffix) and len(n.args) == 2:
                    setter = n
            pname = format_as_camelcase(name[len(method_prefix)+len('get_'):])
            fname = format_as_camelcase(name[len(method_prefix):])
            if not setter:
                print_('    %s = property(%s)' % (pname, fname), file=fd)
            else:
                f2name = format_as_camelcase(setter.name[len(method_prefix):])
                print_('    %s = property(%s, %s)' % (pname, fname, f2name), file=fd)
        if empty:
            print_('    pass', file=fd)
        print_('', file=fd)

    def format_docstring(self, func, method_name, indent):
        if func.args:
            first_arg_name = func.args[0][1]
        else:
            first_arg_name = None

        def format_inlines_sub(s):
            type = s.group(1)[0]
            var = s.group(1)[1:]
            if type == '#': # struct
                if var.startswith('Lasso'):
                    return 'L{%s}' % var[5:]
            elif type == '%': # %TRUE, %FALSE
                if var == 'TRUE':
                    return 'True'
                if var == 'FALSE':
                    return 'False'
                print_('W: unknown docstring thingie: %s' % s.group(1), file=sys.stderr)
            elif type == '@':
                if var == first_arg_name:
                    var = 'self'
                return 'C{%s}' % var
            return s.group(1)

        regex = re.compile(r'([\#%@]\w+)', re.DOTALL)

        def format_inline(s):
            s = regex.sub(format_inlines_sub, s)
            return s.replace('NULL', 'None')

        docstring = func.docstring
        s = []

        if docstring.description:
            for paragraph in docstring.description.split('\n\n'):
                if '<itemizedlist>' in paragraph:
                    before, after = paragraph.split('<itemizedlist>' ,1)
                    if before:
                        s.append('\n'.join(textwrap.wrap(
                                        format_inline(before), 70)))

                    # remove tags
                    after = after.replace('<itemizedlist>', '')
                    after = after.replace('</itemizedlist>', '')

                    for listitem in after.split('<listitem><para>'):
                        listitem = listitem.replace('</para></listitem>', '').strip()
                        s.append('\n'.join(textwrap.wrap(
                                        format_inline(listitem), 70,
                                        initial_indent = ' - ',
                                        subsequent_indent = '   ')))
                        s.append('\n\n')

                else:
                    s.append('\n'.join(textwrap.wrap(
                                    format_inline(paragraph), 70)))
                    s.append('\n\n')

        for param in docstring.parameters:
            s.append('\n'.join(textwrap.wrap(
                            format_inline(param[1]), 70,
                            initial_indent = '@param %s: ' % param[0],
                            subsequent_indent = 4*' ')))
            s.append('\n')
        if docstring.return_value:
            rv = docstring.return_value
            exceptions_instead = ['0 on success; or a negative value otherwise.',
                    '0 on success; a negative value if an error occured.',
                    '0 on success; another value if an error occured.']
            if not rv in exceptions_instead:
                owner_info = ['This xmlnode must be freed by caller.',
                        'The string must be freed by the caller.',
                        'It must be freed by the caller.',
                        'This string must be freed by the caller.']
                for o_i in owner_info:
                    rv = rv.replace(o_i, '')
                s.append('\n'.join(textwrap.wrap(
                                format_inline(rv), 70,
                                initial_indent = '@return: ',
                                subsequent_indent = 4*' ')))
                s.append('\n')


        if s:
            s[-1] = s[-1].rstrip() # remove trailing newline from last line

        return '\n'.join([(indent*' ')+x for x in ''.join(s).splitlines()])


    def generate_functions(self, fd):
        for m in self.binding_data.functions:
            if m.name.endswith('_new') or '_new_' in m.name:
                continue
            if m.rename:
                pname = m.rename
                name = m.rename
                if name.startswith('lasso_'):
                    name = name[6:]
                    pname = format_as_camelcase(name)
            else:
                name = m.name[6:]
                pname = format_as_camelcase(name)
            print_('%s = _lasso.%s' % (pname, name), file=fd)


    def generate_wrapper(self, fd):
        print_(open(os.path.join(self.src_dir,'wrapper_top.c')).read(), file=fd)
        for h in self.binding_data.headers:
            print_('#include <%s>' % h, file=fd)
        print_('', file=fd)

        self.generate_constants_wrapper(fd)

        self.wrapper_list = []
        for m in self.binding_data.functions:
            self.generate_function_wrapper(m, fd)
        for c in self.binding_data.structs:
            self.generate_member_wrapper(c, fd)
            for m in c.methods:
                self.generate_function_wrapper(m, fd)
        self.generate_wrapper_list(fd)
        print_(open(os.path.join(self.src_dir,'wrapper_bottom.c')).read(), file=fd)

    def generate_constants_wrapper(self, fd):
        print_('''static void
register_constants(PyObject *d)
{
    PyObject *obj;
''', file=fd)
        for c in self.binding_data.constants:
            if c[0] == 'i':
                print_('    obj = PyInt_FromLong(%s);' % c[1], file=fd)
            elif c[0] == 's':
                print_('    obj = PyString_FromString((char*)%s);' % c[1], file=fd)
            elif c[0] == 'b':
                print_('''\
#ifdef %s
    obj = Py_True;
#else
    obj = Py_False;
#endif''' % c[1], file=fd)
            else:
                print_('E: unknown constant type: %r' % c[0], file=sys.stderr)
            print_('    PyDict_SetItemString(d, "%s", obj);' % c[1][6:], file=fd)
            print_('    Py_DECREF(obj);', file=fd)
        print_('}', file=fd)
        print_('', file=fd)


    def generate_member_wrapper(self, c, fd):
        klassname = c.name
        for m in c.members:
            name = arg_name(m)
            mname = format_as_camelcase(arg_name(m))
            # getter
            print_('''static PyObject*
%s_%s_get(G_GNUC_UNUSED PyObject *self, PyObject *args)
{''' % (klassname[5:], mname), file=fd)
            self.wrapper_list.append('%s_%s_get' % (klassname[5:], mname))

            ftype = arg_type(m)
            if is_cstring(m):
                ftype = 'char*'
            print_('    %s return_value;' % ftype, file=fd)
            print_('    PyObject* return_pyvalue;', file=fd)
            print_('    PyGObjectPtr* cvt_this;', file=fd)
            print_('    %s* this;' % klassname, file=fd)
            print_('', file=fd)
            print_('    if (! PyArg_ParseTuple(args, "O", &cvt_this)) return NULL;', file=fd)
            print_('    this = (%s*)cvt_this->obj;' % klassname, file=fd)
            print_('    return_value = this->%s;' % arg_name(m), file=fd)
            try:
                self.return_value(fd, m)
            except:
                print_('W: cannot make an assignment for', c, m, file=sys.stderr)
                raise
            print_('    return return_pyvalue;', file=fd)
            print_('}', file=fd)
            print_('', file=fd)

            # setter
            print_('''static PyObject*
%s_%s_set(G_GNUC_UNUSED PyObject *self, PyObject *args)
{''' % (klassname[5:], mname), file=fd)
            self.wrapper_list.append('%s_%s_set' % (klassname[5:], mname))

            print_('    PyGObjectPtr* cvt_this;', file=fd)
            print_('    %s* this;' % klassname, file=fd)
            type = m[0]
            # Determine type class
            if is_cstring(m):
                type = type.replace('const ', '')
                parse_format = 'z'
                parse_arg = '&value'
                print_('    %s value;' % type, file=fd)
            elif is_int(m, self.binding_data):
                parse_format = 'l'
                parse_arg = '&value'
                print_('    long value;', file=fd)
            elif is_glist(m) or is_hashtable(m) or is_xml_node(m) or is_boolean(m):
                parse_format = 'O'
                print_('    PyObject *cvt_value;', file=fd)
                parse_arg = '&cvt_value'
            elif is_object(m):
                parse_format = 'O'
                print_('    PyGObjectPtr *cvt_value;', file=fd)
                parse_arg = '&cvt_value'
            else:
                raise Exception('Unsupported field: %s' % (m,))
            # Get GObject
            print_('    if (! PyArg_ParseTuple(args, "O%s", &cvt_this, %s)) return NULL;' % (
                    parse_format, parse_arg), file=fd)
            print_('    this = (%s*)cvt_this->obj;' % klassname, file=fd)
            # Change value
            if is_int(m, self.binding_data):
                print_('    this->%s = value;' % name, file=fd)
            elif is_boolean(m):
                print_('    this->%s = PyInt_AS_LONG(cvt_value) ? TRUE : FALSE;' % name, file=fd)
            elif is_cstring(m):
                print_('    lasso_assign_string(this->%s, value);' % name, file=fd)
            elif is_xml_node(m):
                print_('    if (this->%s) xmlFreeNode(this->%s);' % (name, name), file=fd)
                print_('    this->%s = get_xml_node_from_pystring(cvt_value);' % name, file=fd)
            elif is_glist(m):
                el_type = element_type(m)
                if is_cstring(el_type):
                    print_('    set_list_of_strings(&this->%s, cvt_value);' % name, file=fd)
                elif is_xml_node(el_type):
                    print_('    set_list_of_xml_nodes(&this->%s, cvt_value);' % name, file=fd)
                elif is_object(el_type):
                    print_('    set_list_of_pygobject(&this->%s, cvt_value);' % name, file=fd)
                else:
                    raise Exception('Unsupported setter for %s' % (m,))
            elif is_hashtable(m):
                el_type = element_type(m)
                if is_object(el_type):
                    print_('    set_hashtable_of_pygobject(this->%s, cvt_value);' % name, file=fd)
                else:
                    print_('    set_hashtable_of_strings(this->%s, cvt_value);' % name, file=fd)
            elif is_object(m):
                print_('    set_object_field((GObject**)&this->%s, cvt_value);' % name, file=fd)
            else:
                raise Exception('Unsupported member %s.%s' % (klassname, m))
            print_('    return noneRef();', file=fd)
            print_('}', file=fd)
            print_('', file=fd)


    def return_value(self, fd, arg, return_var_name = 'return_value', return_pyvar_name = 'return_pyvalue'):
        if is_boolean(arg):
            print_('    if (%s) {' % return_var_name, file=fd)
            print_('        Py_INCREF(Py_True);', file=fd)
            print_('        %s = Py_True;' % return_pyvar_name, file=fd)
            print_('    } else {', file=fd)
            print_('        Py_INCREF(Py_False);', file=fd)
            print_('        %s = Py_False;' % return_pyvar_name, file=fd)
            print_('    }', file=fd)
        elif is_int(arg, self.binding_data):
            print_('    %s = PyInt_FromLong(%s);' % (return_pyvar_name, return_var_name), file=fd)
        elif is_cstring(arg) and is_transfer_full(arg):
            print_('    if (%s) {' % return_var_name, file=fd)
            print_('        %s = PyString_FromString(%s);' % (return_pyvar_name, return_var_name), file=fd)
            print_('    } else {', file=fd)
            print_('        %s = noneRef();' % return_pyvar_name, file=fd)
            print_('    }', file=fd)
        elif is_cstring(arg):
            print_('    if (%s) {' % return_var_name, file=fd)
            print_('        %s = PyString_FromString(%s);' % (return_pyvar_name, return_var_name), file=fd)
            print_('    } else {', file=fd)
            print_('        %s = noneRef();' % return_pyvar_name, file=fd)
            print_('    }', file=fd)
        elif is_glist(arg):
            el_type = element_type(arg)
            if is_object(el_type):
                print_('    %s = get_list_of_pygobject(%s);' % (return_pyvar_name, return_var_name), file=fd)
            elif is_cstring(el_type):
                print_('    %s = get_list_of_strings(%s);' % (return_pyvar_name, return_var_name), file=fd)
            elif is_xml_node(el_type):
                print_('    %s = get_list_of_xml_nodes(%s);' % (return_pyvar_name, return_var_name), file=fd)
            else:
                raise Exception('failed to make an assignment for %s' % (arg,))
        elif is_hashtable(arg):
            el_type = element_type(arg)
            if is_object(el_type):
                print_('    %s = get_dict_from_hashtable_of_objects(%s);' % (return_pyvar_name, return_var_name), file=fd)
            else:
                print_('    %s = get_dict_from_hashtable_of_strings(%s);' % (return_pyvar_name, return_var_name), file=fd)
        elif is_xml_node(arg):
            # convert xmlNode* to strings
            print_('    if (%s) {' % return_var_name, file=fd)
            print_('        %s = get_pystring_from_xml_node(%s);' % (return_pyvar_name, return_var_name), file=fd)
            print_('    } else {', file=fd)
            print_('        %s = noneRef();' % return_pyvar_name, file=fd)
            print_('    }', file=fd)
        elif is_object(arg):
            # return a PyGObjectPtr (wrapper around GObject)
            print_('''\
    if (%s) {
        %s = PyGObjectPtr_New(G_OBJECT(%s));
    } else {
        %s = noneRef();
    }
''' % (return_var_name, return_pyvar_name, return_var_name, return_pyvar_name), file=fd)
        else:
            raise Exception('failed to make an assignment for %s' % (arg,))

    def generate_function_wrapper(self, m, fd):
        if m.rename:
            name = m.rename
            if name.startswith('lasso_'):
                name = name[6:]
        else:
            name = m.name[6:]
        self.wrapper_list.append(name)
        print_('''static PyObject*
%s(G_GNUC_UNUSED PyObject *self, PyObject *args)
{''' % name, file=fd)
        parse_tuple_format = []
        parse_tuple_args = []
        for arg in m.args:
            atype = arg_type(arg)
            aname = arg_name(arg)
            arg_def = None
            python_cvt_def = None
            defval = None
            if is_optional(arg):
                if not '|' in parse_tuple_format:
                    parse_tuple_format.append('|')
            if is_cstring(arg):
                atype = unconstify(atype) 
                if is_optional(arg):
                    parse_tuple_format.append('z')
                else:
                    parse_tuple_format.append('s')
                parse_tuple_args.append('&%s' % aname)
                arg_def = '    %s %s = NULL;' % (arg[0], arg[1])
            elif is_int(arg, self.binding_data) or is_boolean(arg):
                parse_tuple_format.append('i')
                parse_tuple_args.append('&%s' % aname)
                if arg_default(arg):
                    defval = arg_default(arg)
                    if defval.startswith('b:'):
                        defval = defval[2:].upper()
                    else:
                        defval = defval[2:]
                    arg_def = '    %s %s = %s;' % (arg[0], arg[1], defval)
                else:
                    arg_def = '    %s %s;' % (arg[0], arg[1])
            elif is_xml_node(arg) or is_list(arg) or is_time_t_pointer(arg):
                parse_tuple_format.append('O')
                parse_tuple_args.append('&cvt_%s' % aname)
                arg_def = '    %s %s = NULL;' % (arg[0], arg[1])
                python_cvt_def = '    PyObject *cvt_%s = NULL;' % aname
            else:
                parse_tuple_format.append('O')
                parse_tuple_args.append('&cvt_%s' % aname)
                arg_def = '    %s %s = NULL;' % (arg[0], arg[1])
                python_cvt_def = '    PyGObjectPtr *cvt_%s = NULL;' % aname
            if is_out(arg):
                arg_def = '    %s %s = NULL;' % (var_type(arg), arg[1])
                parse_tuple_format.pop()
                parse_tuple_format.append('O')
                parse_tuple_args.pop()
                parse_tuple_args.append('&cvt_%s_out' % aname)
                python_cvt_def = '    PyObject *cvt_%s_out = NULL;' % aname
                print_('    PyObject *out_pyvalue = NULL;', file=fd)
            print_(arg_def, file=fd)
            if python_cvt_def:
                print_(python_cvt_def, file=fd)

        if m.return_type:
            print_('    %s return_value;' % m.return_type, file=fd)
            print_('    PyObject* return_pyvalue = NULL;', file=fd)
        print_('', file=fd)

        parse_tuple_args = ', '.join(parse_tuple_args)
        if parse_tuple_args:
            parse_tuple_args = ', ' + parse_tuple_args

        print_('    if (! PyArg_ParseTuple(args, "%s"%s)) return NULL;' % (
                ''.join(parse_tuple_format), parse_tuple_args), file=fd)

        for f, arg in zip([ x for x in parse_tuple_format if x != '|'], m.args):
            if is_out(arg):
                continue
            if is_list(arg):
                qualifier = element_type(arg)
                if is_cstring(qualifier):
                    print_('    set_list_of_strings(&%s, cvt_%s);' % (arg[1], arg[1]), file=fd)
                elif qualifier == 'xmlNode*':
                    print_('    set_list_of_xml_nodes(&%s, cvt_%s);' % (arg[1], arg[1]), file=fd)
                elif isinstance(qualifier, str) and qualifier.startswith('Lasso'):
                    print_('    set_list_of_pygobject(&%s, cvt_%s);' % (arg[1], arg[1]), file=fd)
                else:
                    print_('E: unqualified GList argument in', name, qualifier, arg, file=sys.stderr)
            elif is_xml_node(arg):
                print_('    %s = get_xml_node_from_pystring(cvt_%s);' % (arg[1], arg[1]), file=fd)
            elif is_time_t_pointer(arg):
                print_('    %s = get_time_t(cvt_%s);' % (arg[1], arg[1]), file=fd)
            elif f == 'O':
                if is_optional(arg):
                    print_('    if (PyObject_TypeCheck((PyObject*)cvt_%s, &PyGObjectPtrType)) {' % arg[1], file=fd)
                    print_('        %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1]), file=fd)
                    print_('    } else {', file=fd)
                    print_('        %s = NULL;' % arg[1], file=fd)
                    print_('    }', file=fd)
                else:
                    print_('    if (PyObject_TypeCheck((PyObject*)cvt_%s, &PyGObjectPtrType)) {' % arg[1], file=fd)
                    print_('        %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1]), file=fd)
                    print_('    } else {', file=fd)
                    print_('        PyErr_SetString(PyExc_TypeError, "value should be a PyGObject");', file=fd)
                    print_('        return NULL;', file=fd)
                    print_('    }', file=fd)


        if m.return_type:
            print_('    return_value =', file=fd)
            if 'new' in m.name:
                print_('(%s)' % m.return_type, file=fd)
        else:
            print_('   ', file=fd)
        print_('%s(%s);' % (m.name, ', '.join([ref_name(x) for x in m.args])), file=fd)

        if m.return_type:
            # Constructor so decrease refcount (it was incremented by PyGObjectPtr_New called
            # in self.return_value
            try:
                self.return_value(fd, m.return_arg)
            except:
                print_('W: cannot assign return value of', m, file=sys.stderr)
                raise

            if is_transfer_full(m.return_arg, default=True):
                self.free_value(fd, m.return_arg, name = 'return_value')
        for f, arg in zip(parse_tuple_format, m.args):
            if is_out(arg):
                self.return_value(fd, arg, return_var_name = arg[1], return_pyvar_name = 'out_pyvalue')
                print_('    PyList_SetItem(cvt_%s_out, 0, out_pyvalue);' % arg[1], file=fd)
            elif arg[0] == 'GList*':
                qualifier = arg[2].get('element-type')
                if qualifier == 'char*':
                    print_('    free_list(&%s, (GFunc)g_free);' % arg[1], file=fd)
                elif qualifier == 'xmlNode*':
                    print_('    free_list(&%s, (GFunc)xmlFreeNode);' % arg[1], file=fd)
                elif qualifier == 'LassoNode':
                    print_('    free_list(&%s, (GFunc)g_object_unref);' % arg[1], file=fd)
            elif is_time_t_pointer(arg):
                print_('    if (%s) free(%s);' % (arg[1], arg[1]), file=fd)
            elif not is_transfer_full(arg) and is_xml_node(arg):
                self.free_value(fd, arg)

        if not m.return_type:
            print_('    return noneRef();', file=fd)
        else:
            print_('    return return_pyvalue;', file=fd)
        print_('}', file=fd)
        print_('', file=fd)

    def generate_wrapper_list(self, fd):
        print_('''
static PyMethodDef lasso_methods[] = {''', file=fd)
        for m in self.wrapper_list:
            print_('    {"%s", %s, METH_VARARGS, NULL},' % (m, m), file=fd)
        print_('    {NULL, NULL, 0, NULL}', file=fd)
        print_('};', file=fd)
        print_('', file=fd)

