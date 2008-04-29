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

class PythonBinding:
    def __init__(self, binding_data):
        self.binding_data = binding_data

    def is_pygobject(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*',
                'GList*', 'GHashTable*',
                'int', 'gint', 'gboolean', 'const gboolean', 'xmlNode*'] + self.binding_data.enums

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
        print >> fd, '''\
# this file has been generated automatically; do not edit

import _lasso

_lasso.init()

def cptrToPy(cptr):
    if cptr is None:
        return None
    klass = getattr(lasso, cptr.typename)
    o = klass.__new__(klass)
    o._cptr = cptr
    return o

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
'''

    def generate_exceptions(self, fd):
        done_cats = []
        print >> fd, '''\
class Error(Exception):
    code = None
    
    @staticmethod
    def raise_on_rc(rc):
        global exceptions_dict
        exception = exceptions_dict.get(rc, Error())
        exception.code = rc
        raise exception

    def __str__(self):
        return '<lasso.%s(%s): %s>' % (self.__class__.__name__, self.code, _lasso.strError(self.code))

    def __getitem__(self, i):
        # compatibility with SWIG bindings
        if i == 0:
            return self.code
        elif i == 1:
            return _lasso.strError(self.code)
        else:
            raise IndexError()
'''
        for exc_cat in self.binding_data.overrides.findall('exception/category'):
            cat = exc_cat.attrib.get('name')
            done_cats.append(cat)
            parent_cat = exc_cat.attrib.get('parent', '')
            print >> fd, '''\
class %sError(%sError):
    pass
''' % (cat, parent_cat)

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

                print >> fd, '''\
class %sError(%sError):
    pass
''' % (cat, parent_cat)

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

            print >> fd, '''\
class %sError(%sError):
    pass
''' % (detail, cat)

        print >> fd, 'exceptions_dict = {'
        for k, v in exceptions_dict.items():
            print >> fd, '    _lasso.%s: %sError,' % (v, k)
        print >> fd, '}'
        print >> fd, ''

    def generate_footer(self, fd):
        print >> fd, '''

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
'''

    def generate_constants(self, fd):
        print >> fd, '### Constants (both enums and defines)'
        for c in self.binding_data.constants:
            print >> fd, '%s = _lasso.%s' % (c[1][6:], c[1][6:])
        for c in self.binding_data.overrides.findall('constant'):
            name = c.attrib.get('name')
            if c.attrib.get('value'):
                name = name[6:] # dropping LASSO_
                value = c.attrib.get('value')
                if value == 'True':
                    print >> fd, '%s = True' % name
                else:
                    print >> sys.stderr, 'E: unknown value for constant: %r' % value
        print >> fd, ''

    def generate_class(self, clss, fd):
        klassname = clss.name[5:] # remove Lasso from class name
        if clss.parent == 'GObject':
            parentname = 'object'
        else:
            parentname = clss.parent[5:]

        print >> fd, '''class %(klassname)s(%(parentname)s):''' % locals()
        if not clss.members and not clss.methods:
            print >> fd, '    pass'
            print >> fd, ''
            return

        methods = clss.methods[:]
        # constructor(s)
        method_prefix = 'lasso_' + utils.format_as_underscored(klassname) + '_'
        for m in self.binding_data.functions:
            if m.name == method_prefix + 'new':
                c_args = []
                py_args = []
                for o in m.args:
                    arg_type, arg_name, arg_options = o
                    if arg_options.get('optional'):
                        py_args.append('%s = None' % arg_name)
                    else:
                        py_args.append(arg_name)

                    if self.is_pygobject(arg_type):
                        c_args.append('%s._cptr' % arg_name)
                    else:
                        c_args.append(arg_name)
                    
                c_args = ', '.join(c_args)
                py_args = ', ' + ', '.join(py_args)
                print >> fd, '    def __init__(self%s):' % py_args
                # XXX: could check self._cptr.typename to see if it got the
                # right class type
                print >> fd, '        self._cptr = _lasso.%s(%s)' % (
                        m.name[6:], c_args)
                print >> fd, '        if self._cptr is None:'
                print >> fd, '            raise Error(\'failed to create object\')'
                print >> fd, ''

        for m in self.binding_data.functions:
            if m.name.startswith(method_prefix + 'new_'):
                constructor_name = utils.format_as_camelcase(m.name[len(method_prefix):])
                c_args = []
                py_args = []
                for o in m.args:
                    arg_type, arg_name, arg_options = o
                    if arg_options.get('optional'):
                        py_args.append('%s = None' % arg_name)
                    else:
                        py_args.append(arg_name)

                    if self.is_pygobject(arg_type):
                        c_args.append('%s._cptr' % arg_name)
                    else:
                        c_args.append(arg_name)
                c_args = ', '.join(c_args)
                py_args = ', ' + ', '.join(py_args)
                print >> fd, '    @classmethod'
                print >> fd, '    def %s(cls%s):' % (constructor_name, py_args)
                print >> fd, '         obj = cls.__new__(cls)'
                print >> fd, '         obj._cptr = _lasso.%s(%s)' % (m.name[6:], c_args)
                print >> fd, '         if obj._cptr is None:'
                print >> fd, '             raise RuntimeError(\'lasso failed to create object\')'
                print >> fd, '         return obj'
                print >> fd, ''

        # create properties for members
        for m in clss.members:
            mname = utils.format_as_camelcase(m[1])
            options = m[2]
            print >> fd, '    def get_%s(self):' % mname
            if self.is_pygobject(m[0]):
                print >> fd, '        t = _lasso.%s_%s_get(self._cptr)' % (
                        klassname, mname)
                print >> fd, '        return cptrToPy(t)'
            elif m[0] == 'GList*' and options.get('elem_type') not in ('char*', 'xmlNode*'):
                print >> fd, '        l = _lasso.%s_%s_get(self._cptr)' % (
                        klassname, mname)
                print >> fd, '        if not l: return l'
                print >> fd, '        return tuple([cptrToPy(x) for x in l])'
            elif m[0] == 'GHashTable*':
                print >> fd, '        d = _lasso.%s_%s_get(self._cptr)' % (
                        klassname, mname)
                print >> fd, '        if not d: return d'
                if options.get('elem_type') != 'char*':
                    print >> fd, '        d2 = {}'
                    print >> fd, '        for k, v in d.items():'
                    print >> fd, '            d2[k] = cptrToPy(v)'
                    print >> fd, '        return frozendict(d2)'
                else:
                    print >> fd, '        return frozendict(d)'
            else:
                print >> fd, '        return _lasso.%s_%s_get(self._cptr)' % (
                        klassname, mname)
            print >> fd, '    def set_%s(self, value):' % mname
            if self.is_pygobject(m[0]):
                print >> fd, '        if value is not None:'
                print >> fd, '            value = value._cptr'
            elif m[0] == 'GList*' and options.get('elem_type') not in ('char*', 'xmlNode*'):
                print >> fd, '        if value is not None:'
                print >> fd, '            value = tuple([x._cptr for x in value])'
            print >> fd, '        _lasso.%s_%s_set(self._cptr, value)' % (
                    klassname, mname)
            print >> fd, '    %s = property(get_%s, set_%s)' % (mname, mname, mname)
            print >> fd, ''

        # first pass on methods, getting accessors
        for m in clss.methods:
            if not ('_get_' in m.name and len(m.args) == 1):
                continue
            methods.remove(m)
            try:
                setter_name = m.name.replace('_get_', '_set_')
                setter = [x for x in methods if x.name == setter_name][0]
                methods.remove(setter)
            except IndexError:
                setter = None
            if m.rename:
                mname = m.rename
                if mname.startswith('lasso_'):
                    mname = mname[6:]
                mname = '%s%s' % (mname[0].lower(), mname[1:])
                print >> fd, '    def get_%s(self):' % mname
                function_name = m.rename
                if function_name.startswith('lasso_'):
                    function_name = function_name[6:]
            else:
                mname = m.name
                mname = re.match(r'lasso_.*_get_(\w+)', mname).group(1)
                mname = utils.format_underscore_as_camelcase(mname)
                print >> fd, '    def get_%s(self):' % mname
                function_name = m.name[6:]

            if self.is_pygobject(m.return_type):
                print >> fd, '        t = _lasso.%s(self._cptr)' % function_name
                print >> fd, '        return cptrToPy(t)'
            else:
                print >> fd, '        return _lasso.%s(self._cptr)' % function_name

            if mname[0] == mname[0].lower() and not m.rename:
                # API compatibility with SWIG bindings which didn't have
                # accessors for those methods and used totally pythonified
                # method name instead, such as getNextProviderId
                print >> fd, '    get%s%s = get_%s' % (
                        mname[0].upper(), mname[1:], mname)
            if setter:
                print >> fd, '    def set_%s(self, value):' % mname
                print >> fd, '        _lasso.%s(self._cptr, value)' % setter.name[6:]
                print >> fd, '    %s = property(get_%s, set_%s)' % (mname, mname, mname)
            else:
                print >> fd, '    %s = property(get_%s)' % (mname, mname)
            print >> fd, ''

        # second pass on methods, real methods
        for m in methods:
            if m.name.endswith('_new') or m.name.endswith('_new_from_dump') or \
                    m.name.endswith('_new_full'):
                continue
            if not m.name.startswith(method_prefix):
                print >> sys.stderr, 'W:', m.name, 'vs', method_prefix
                continue

            if m.rename:
                mname = m.rename[len(method_prefix):]
                function_name = m.rename[6:]
            else:
                mname = m.name[len(method_prefix):]
                function_name = m.name[6:]
            py_args = []
            c_args = []
            for o in m.args[1:]:
                arg_type, arg_name, arg_options = o
                if arg_options.get('optional'):
                    if arg_options.get('default'):
                        defval = arg_options.get('default')
                        if defval.startswith('c:'): # constant
                            py_args.append('%s = %s' % (arg_name, defval[8:]))
                        elif defval.startswith('b:'): # boolean
                            py_args.append('%s = %s' % (arg_name, defval[2:]))
                        else:
                            print >> sys.stderr, "E: don't know what to do with %s" % defval
                            sys.exit(1)
                    else:
                        py_args.append('%s = None' % arg_name)
                else:
                    py_args.append(arg_name)
                if arg_type in ('char*', 'const char*', 'gchar*', 'const gchar*') or \
                        arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] or \
                        arg_type in self.binding_data.enums:
                    c_args.append(arg_name)
                else:
                    c_args.append('%s._cptr' % arg_name)

            if py_args:
                py_args = ', ' + ', '.join(py_args)
            else:
                py_args = ''
            if c_args:
                c_args = ', ' + ', '.join(c_args)
            else:
                c_args = ''

            print >> fd, '    def %s(self%s):' % (
                    utils.format_underscore_as_camelcase(mname), py_args)
            if m.docstring:
                print >> fd, "        '''"
                print >> fd, self.format_docstring(m, mname, 8)
                print >> fd, "        '''"
            if m.return_type in (None, 'void'):
                print >> fd, '        _lasso.%s(self._cptr%s)' % (
                        function_name, c_args)
            elif m.return_type in ('gint', 'int'):
                print >> fd, '        rc = _lasso.%s(self._cptr%s)' % (
                        function_name, c_args)
                print >> fd, '        if rc == 0:'
                print >> fd, '            return'
                print >> fd, '        raise Error.raise_on_rc(rc)'
            elif m.return_type == 'GList*' and self.is_pygobject(m.return_type_qualifier):
                print >> fd, '        value = _lasso.%s(self._cptr%s)' % (
                        function_name, c_args)
                print >> fd, '        if value is not None:'
                print >> fd, '            value = tuple([cptrToPy(x) for x in value])'
                print >> fd, '        return value'
            elif self.is_pygobject(m.return_type):
                print >> fd, '        return cptrToPy(_lasso.%s(self._cptr%s))' % (
                        function_name, c_args)
            else:
                print >> fd, '        return _lasso.%s(self._cptr%s)' % (
                        function_name, c_args)
            print >> fd, ''

        print >> fd, ''

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
                print >> sys.stderr, 'W: unknown docstring thingie: %s' % s.group(1)
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
                    pname = utils.format_as_camelcase(name)
            else:
                name = m.name[6:]
                pname = utils.format_as_camelcase(name)
            print >> fd, '%s = _lasso.%s' % (pname, name)


    def generate_wrapper(self, fd):
        print >> fd, open(os.path.join(self.binding_data.src_dir, 
                    'lang_python_wrapper_top.c')).read()
        for h in self.binding_data.headers:
            print >> fd, '#include <%s>' % h
        print >> fd, ''

        self.generate_constants_wrapper(fd)

        self.wrapper_list = []
        for m in self.binding_data.functions:
            self.generate_function_wrapper(m, fd)
        for c in self.binding_data.structs:
            self.generate_member_wrapper(c, fd)
            for m in c.methods:
                self.generate_function_wrapper(m, fd)
        self.generate_wrapper_list(fd)
        print >> fd, open(os.path.join(self.binding_data.src_dir,
                    'lang_python_wrapper_bottom.c')).read()

    def generate_constants_wrapper(self, fd):
        print >> fd, '''static void
register_constants(PyObject *d)
{
    PyObject *obj;
'''
        for c in self.binding_data.constants:
            if c[0] == 'i':
                print >> fd, '    obj = PyInt_FromLong(%s);' % c[1]
            elif c[0] == 's':
                print >> fd, '    obj = PyString_FromString(%s);' % c[1]
            elif c[0] == 'b':
                print >> fd, '''\
#ifdef %s
    obj = Py_True;
#else
    obj = Py_False;
#endif''' % c[1]
            else:
                print >> sys.stderr, 'E: unknown constant type: %r' % c[0]
            print >> fd, '    PyDict_SetItemString(d, "%s", obj);' % c[1][6:]
            print >> fd, '    Py_DECREF(obj);'
        print >> fd, '}'
        print >> fd, ''


    def generate_member_wrapper(self, c, fd):
        klassname = c.name
        for m in c.members:
            mname = utils.format_as_camelcase(m[1])
            # getter
            print >> fd, '''static PyObject*
%s_%s_get(PyObject *self, PyObject *args)
{''' % (klassname[5:], mname)
            self.wrapper_list.append('%s_%s_get' % (klassname[5:], mname))

            ftype = m[0]
            if ftype in ('char*', 'const char*', 'gchar*', 'const gchar*'):
                ftype = 'char*'
            print >> fd, '    %s return_value;' % ftype
            print >> fd, '    PyObject* return_pyvalue;'
            print >> fd, '    PyGObjectPtr* cvt_this;'
            print >> fd, '    %s* this;' % klassname
            print >> fd, ''
            print >> fd, '    if (! PyArg_ParseTuple(args, "O", &cvt_this)) return NULL;'
            print >> fd, '    this = (%s*)cvt_this->obj;' % klassname

            if self.is_pygobject(ftype):
                print >> fd, '    return_value = this->%s;' % m[1];
            elif ftype in ('char*',):
                print >> fd, '    return_value = g_strdup(this->%s);' % m[1]
            else:
                print >> fd, '    return_value = this->%s;' % m[1];

            self.return_value(fd, ftype, m[2])

            print >> fd, '    return return_pyvalue;'
            print >> fd, '}'
            print >> fd, ''

            # setter
            print >> fd, '''static PyObject*
%s_%s_set(PyObject *self, PyObject *args)
{''' % (klassname[5:], mname)
            self.wrapper_list.append('%s_%s_set' % (klassname[5:], mname))

            print >> fd, '    PyGObjectPtr* cvt_this;'
            print >> fd, '    %s* this;' % klassname
            arg_type = m[0]
            # Determine type class
            if m[0] in ('char*', 'const char*', 'gchar*', 'const gchar*'):
                arg_type = arg_type.replace('const ', '')
                parse_format = 'z'
                parse_arg = '&value'
                print >> fd, '    %s value;' % arg_type
            elif arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums:
                parse_format = 'i'
                parse_arg = '&value'
                print >> fd, '    %s value;' % arg_type
            elif arg_type in ('GList*','GHashTable*', 'xmlNode*'):
                parse_format = 'O'
                print >> fd, '    PyObject *cvt_value;'
                parse_arg = '&cvt_value'
            else:
                parse_format = 'O'
                print >> fd, '    PyGObjectPtr *cvt_value;'
                parse_arg = '&cvt_value'
            # Get GObject
            print >> fd, '    if (! PyArg_ParseTuple(args, "O%s", &cvt_this, %s)) return NULL;' % (
                    parse_format, parse_arg)
            print >> fd, '    this = (%s*)cvt_this->obj;' % klassname
            # Change value
            if parse_format == 'i':
                print >> fd, '    this->%s = value;' % m[1]
            elif parse_format in ('s', 'z'):
                print >> fd, '    if (this->%s) g_free(this->%s);' % (m[1], m[1])
                print >> fd, '    this->%s = g_strdup(value);' % m[1]
            elif parse_format == 'O' and arg_type == 'GList*':
                elem_type = m[2].get('elem_type')
                if elem_type == 'char*':
                    print >> fd, '    set_list_of_strings(&this->%s, cvt_value);' % m[1]
                elif elem_type == 'xmlNode*':
                    print >> fd, '    set_list_of_xml_nodes(&this->%s, cvt_value);' % m[1]
                else:
                    print >> fd, '    set_list_of_pygobject(&this->%s, cvt_value);' % m[1]
            elif parse_format == 'O' and arg_type == 'GHashTable*':
                print >> fd, '    set_hashtable_of_pygobject(this->%s, cvt_value);' % m[1]
            elif parse_format == 'O' and arg_type == 'xmlNode*':
                print >> fd, '    if (this->%s) xmlFreeNode(this->%s);' % (m[1], m[1])
                print >> fd, '    this->%s = get_xml_node_from_pystring(cvt_value);' % m[1]
            elif parse_format == 'O':
                print >> fd, '    set_object_field((GObject**)&this->%s, cvt_value);' % m[1]
            print >> fd, '    return noneRef();'
            print >> fd, '}'
            print >> fd, ''


    def return_value(self, fd, vtype, options):
        if vtype == 'gboolean':
            print >> fd, '    if (return_value) {'
            print >> fd, '        Py_INCREF(Py_True);'
            print >> fd, '        return_pyvalue = Py_True;'
            print >> fd, '    } else {'
            print >> fd, '        Py_INCREF(Py_False);'
            print >> fd, '        return_pyvalue = Py_False;'
            print >> fd, '    }'
        elif vtype in ['int', 'gint'] + self.binding_data.enums:
            print >> fd, '    return_pyvalue = PyInt_FromLong(return_value);'
        elif vtype in ('char*', 'gchar*'):
            print >> fd, '    if (return_value) {'
            print >> fd, '        return_pyvalue = PyString_FromString(return_value);'
            print >> fd, '        g_free(return_value);'
            print >> fd, '    } else {'
            print >> fd, '        return_pyvalue = noneRef();'
            print >> fd, '    }'
        elif vtype in ('const char*', 'const gchar*'):
            print >> fd, '    if (return_value) {'
            print >> fd, '        return_pyvalue = PyString_FromString(return_value);'
            print >> fd, '    } else {'
            print >> fd, '        return_pyvalue = noneRef();'
            print >> fd, '    }'
        elif vtype in ('GList*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                print >> fd, '    return_pyvalue = get_list_of_strings(return_value);'
            elif elem_type == 'xmlNode*':
                print >> fd, '    return_pyvalue = get_list_of_xml_nodes(return_value);'
            else:
                print >> fd, '    return_pyvalue = get_list_of_pygobject(return_value);'
        elif vtype in ('GHashTable*',):
            elem_type = options.get('elem_type')
            if elem_type == 'char*':
                print >> fd, '    return_pyvalue = get_dict_from_hashtable_of_strings(return_value);'
            else:
                print >> fd, '    return_pyvalue = get_dict_from_hashtable_of_objects(return_value);'
        elif vtype == 'xmlNode*':
            # convert xmlNode* to strings
            print >> fd, '    if (return_value) {'
            print >> fd, '        return_pyvalue = get_pystring_from_xml_node(return_value);'
            print >> fd, '    } else {'
            print >> fd, '        return_pyvalue = noneRef();'
            print >> fd, '    }'
        else:
            # return a PyGObjectPtr (wrapper around GObject)
            print >> fd, '''\
    if (return_value) {
        return_pyvalue = PyGObjectPtr_New(G_OBJECT(return_value));
    } else {
        return_pyvalue = noneRef();
    }
'''

    def generate_function_wrapper(self, m, fd):
        if m.rename:
            name = m.rename
            if name.startswith('lasso_'):
                name = name[6:]
        else:
            name = m.name[6:]
        self.wrapper_list.append(name)
        print >> fd, '''static PyObject*
%s(PyObject *self, PyObject *args)
{''' % name
        parse_tuple_format = []
        parse_tuple_args = []
        for arg in m.args:
            arg_type, arg_name, arg_options = arg
            if arg_type in ('char*', 'const char*', 'gchar*', 'const gchar*'):
                arg_type = arg_type.replace('const ', '')
                if arg_options.get('optional'):
                    if not '|' in parse_tuple_format:
                        parse_tuple_format.append('|')
                    parse_tuple_format.append('z')
                else:
                    parse_tuple_format.append('s')
                parse_tuple_args.append('&%s' % arg_name)
                print >> fd, '    %s %s = NULL;' % (arg[0], arg[1])
            elif arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums:
                parse_tuple_format.append('i')
                parse_tuple_args.append('&%s' % arg_name)
                print >> fd, '    %s %s;' % (arg[0], arg[1])
            elif arg_type == 'GList*':
                print >> fd, '    %s %s = NULL;' % (arg[0], arg[1])
                print >> fd, '    PyObject *cvt_%s = NULL;' % arg_name
                parse_tuple_format.append('O')
                parse_tuple_args.append('&cvt_%s' % arg_name)
            else:
                parse_tuple_format.append('O')
                parse_tuple_args.append('&cvt_%s' % arg_name)
                print >> fd, '    %s %s = NULL;' % (arg[0], arg[1])
                print >> fd, '    PyGObjectPtr *cvt_%s = NULL;' % arg_name

        if m.return_type:
            print >> fd, '    %s return_value;' % m.return_type
            print >> fd, '    PyObject* return_pyvalue;'
        print >> fd, ''

        parse_tuple_args = ', '.join(parse_tuple_args)
        if parse_tuple_args:
            parse_tuple_args = ', ' + parse_tuple_args

        print >> fd, '    if (! PyArg_ParseTuple(args, "%s"%s)) return NULL;' % (
                ''.join(parse_tuple_format), parse_tuple_args)

        for f, arg in zip(parse_tuple_format, m.args):
            if arg[0] == 'GList*':
                qualifier = arg[2].get('elem_type')
                if qualifier == 'char*':
                    print >> fd, '    set_list_of_strings(&%s, cvt_%s);' % (arg[1], arg[1])
                elif qualifier == 'xmlNode*':
                    print >> fd, '    set_list_of_xml_nodes(&%s, cvt_%s);' % (arg[1], arg[1])
                elif qualifier == 'LassoNode':
                    print >> fd, '    set_list_of_pygobject(&%s, cvt_%s);' % (arg[1], arg[1])
                else:
                    print >> sys.stderr, 'E: unqualified GList argument in', name
            elif f == 'O':
                print >> fd, '    %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1])

        if m.return_type:
            print >> fd, '    return_value =',
            if 'new' in m.name:
                print >> fd, '(%s)' % m.return_type,
        print >> fd, '%s(%s);' % (m.name, ', '.join([x[1] for x in m.args]))

        for f, arg in zip(parse_tuple_format, m.args):
            if arg[0] == 'GList*':
                qualifier = arg[2].get('elem_type')
                if qualifier == 'char*':
                    print >> fd, '    free_list(&%s, (GFunc)g_free);' % arg[1]
                elif qualifier == 'xmlNode*':
                    print >> fd, '    free_list(&%s, (GFunc)xmlFreeNode);' % arg[1]
                elif qualifier == 'LassoNode':
                    print >> fd, '    free_list(&%s, (GFunc)g_object_unref);' % arg[1]

        if not m.return_type:
            print >> fd, '    return noneRef();'
        else:
            # Constructor so decrease refcount (it was incremented by PyGObjectPtr_New called
            # in self.return_value
            self.return_value(fd, m.return_type, {'elem_type': m.return_type_qualifier})
            if m.return_owner and self.is_pygobject(m.return_type):
                print >> fd, '    if (return_value) g_object_unref(return_value);'
            print >> fd, '    return return_pyvalue;'
        print >> fd, '}'
        print >> fd, ''

    def generate_wrapper_list(self, fd):
        print >> fd, '''
static PyMethodDef lasso_methods[] = {'''
        for m in self.wrapper_list:
            print >> fd, '    {"%s", %s, METH_VARARGS, NULL},' % (m, m)
        print >> fd, '    {NULL, NULL, 0, NULL}'
        print >> fd, '};'
        print >> fd, ''

