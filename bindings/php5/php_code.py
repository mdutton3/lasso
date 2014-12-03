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
import sys
import six

from utils import *

class PhpCode:
    def __init__(self, binding_data, fd):
        self.binding_data = binding_data
        self.fd = fd

    def is_object(self, t):
        return is_object(t) and not is_int(t, self.binding_data)

    def generate(self):
        self.generate_header()
        for klass in self.binding_data.structs:
            self.generate_class(klass)
        self.generate_exceptions()
        self.generate_footer()

    def generate_header(self):
        six.print_('''\
<?php

/* this file has been generated automatically; do not edit */

/**
 * @package Lasso
 */

// Try to load Lasso extension if it's not already loaded.
if (!extension_loaded('lasso')) {
    die("Lasso extension is not loaded");
}

/**
 * @package Lasso
 *
 * Root class of all Lasso objects to define generic getter and setter
 */
class LassoObject {
    /**
     * @return mixed
     */
    public function __get($attr) {
        $func = "get_" . $attr;
        if (method_exists($this, $func)) {
            return call_user_func(array($this, $func));
        }
        return null;
    }

    public function __set($attr, $value) {
        $func = "set_" . $attr;
        if (method_exists($this, $func)) {
            call_user_func(array($this, $func), $value);
        }
    }
}

/*
 * Convert a C object to a PHP object
 */
function cptrToPhp ($cptr) {
    if (is_null($cptr) || !$cptr) return null;
    $typename = lasso_get_object_typename($cptr);
    $class_name = $typename . "NoInit";
    $obj = new $class_name();
    if (! is_null($obj)) {
        $obj->_cptr = $cptr;
        return $obj;
    }
    return null;
}

function lassoGetRequestTypeFromSoapMsg($mesg) {
    return lasso_get_request_type_from_soap_msg($mesg);
}

function lassoRegisterIdWsf2DstService($prefix, $href) {
    lasso_register_idwsf2_dst_service($prefix, $href);
}
''', file=self.fd)

    def generate_class(self, klass):
        class_name = klass.name

        if klass.parent != 'GObject':
            inheritence = ' extends %s' % klass.parent
        else:
            inheritence = ' extends LassoObject'

        six.print_('/**', file=self.fd)
        six.print_(' * @package Lasso', file=self.fd)
        six.print_(' */', file=self.fd)
        six.print_('class %(class_name)s%(inheritence)s {' % locals(), file=self.fd)

        if klass.members or klass.methods:
            self.generate_constructors(klass)
            self.generate_getters_and_setters(klass)
            self.generate_methods(klass)

        six.print_('}', file=self.fd)
        six.print_('', file=self.fd)

        # Add a special class to get an object instance without initialising
        six.print_('/**', file=self.fd)
        six.print_(' * @package Lasso', file=self.fd)
        six.print_(' */', file=self.fd)
        six.print_('class %(class_name)sNoInit extends %(class_name)s {' % locals(), file=self.fd)
        six.print_('    public function __construct() {}', file=self.fd)
        six.print_('}', file=self.fd)
        six.print_('', file=self.fd)

    def generate_constructors(self, klass):
        method_prefix = format_as_underscored(klass.name) + '_'
        for m in self.binding_data.functions:
            name = m.rename or m.name
            if m.name == method_prefix + 'new':
                php_args = []
                c_args = []
                for arg in m.args:
                    arg_type, arg_name, arg_options = arg
                    if arg_options.get('optional'):
                        php_args.append('$%s = null' % arg_name)
                    else:
                        php_args.append('$%s' % arg_name)

                    if self.is_object(arg_type):
                        c_args.append('$%s->_cptr' % arg_name)
                    else:
                        c_args.append('$%s' % arg_name)

                php_args = ', '.join(php_args)
                c_args = ', '.join(c_args)
                # XXX: could check $this->_cptr->typename to see if it got the
                # right class type
                six.print_('    public $_cptr = null;', file=self.fd)
                six.print_('', file=self.fd)
                six.print_('    public function __construct(%s) {' % php_args, file=self.fd)
                six.print_('        $this->_cptr = %s(%s);' % (m.name, c_args), file=self.fd)
                six.print_('        if (is_null($this->_cptr)) { throw new Exception("Constructor for ', klass.name, ' failed "); }', file=self.fd)
                six.print_('    }', file=self.fd)
                six.print_('', file=self.fd)

            elif name.startswith(method_prefix) and m.args \
                    and clean_type(unconstify(m.args[0][0])) != klass.name:
                if m.rename:
                    php_name = m.rename
                else:
                    mname = m.name
                    mname = mname[len(method_prefix):]
                    if 'new' in mname and not mname.startswith('new'):
                        continue
                    php_name = format_underscore_as_camelcase(mname)
                php_args = []
                c_args = []
                for arg in m.args:
                    arg_type, arg_name, arg_options = arg
                    if arg_options.get('optional'):
                        php_args.append('$%s = null' % arg_name)
                    else:
                        php_args.append('$%s' % arg_name)

                    if self.is_object(arg_type):
                        c_args.append('$%s->_cptr' % arg_name)
                    else:
                        c_args.append('$%s' % arg_name)
                php_args = ', '.join(php_args)
                c_args = ', '.join(c_args)
                six.print_('    public static function %s(%s) {' % (php_name, php_args), file=self.fd)
                six.print_('        return cptrToPhp(%s(%s));' % (m.name, c_args), file=self.fd)
                six.print_('    }', file=self.fd)
                six.print_('', file=self.fd)



    def generate_getter(self, c, m):
        d = { 'type': arg_type(m), 'name': format_as_camelcase(arg_name(m)),
                'docstring': self.get_docstring_return_type(arg_type(m)), 'class': c.name }

        six.print_('''    /**', file=self.fd)
    * @return %(docstring)s
    */
    protected function get_%(name)s() {''' % d, file=self.fd)
        six.print_('        $t = %(class)s_%(name)s_get($this->_cptr);' % d, file=self.fd)
        if is_object(m):
            six.print_('        $t = cptrToPhp($t);', file=self.fd)
        elif (is_glist(m) or is_hashtable(m)) and is_object(element_type(m)):
                six.print_('        foreach ($t as $key => $item) {', file=self.fd)
                six.print_('            $t[$key] = cptrToPhp($item);', file=self.fd)
                six.print_('        }', file=self.fd)
        elif is_hashtable(m) or (is_glist(m) and (is_cstring(element_type(m)) \
                or is_xml_node(element_type(m)))) or is_int(m, self.binding_data) \
                or is_boolean(m) or is_cstring(m) or is_xml_node(m):
            pass
        else:
            raise Exception('Cannot generate a Php getter %s.%s' % (c,m))
        six.print_('        return $t;', file=self.fd)
        six.print_('    }', file=self.fd)

    def generate_setter(self, c, m):
        d = { 'type': arg_type(m), 'name': format_as_camelcase(arg_name(m)),
                'docstring': self.get_docstring_return_type(arg_type(m)), 'class': c.name }
        six.print_('    protected function set_%(name)s($value) {' % d, file=self.fd)
        if is_object(m):
            six.print_('        $value = $value->_cptr;', file=self.fd)
        elif (is_glist(m) or is_hashtable(m)) and is_object(element_type(m)):
            six.print_('        $array = array();', file=self.fd)
            six.print_('        if (!is_null($value)) {', file=self.fd)
            six.print_('            foreach ($value as $key => $item) {', file=self.fd)
            six.print_('                $array[$key] = $item->_cptr;', file=self.fd)
            six.print_('            }', file=self.fd)
            six.print_('        }', file=self.fd)
            six.print_('        $value = $array;', file=self.fd)
        elif is_hashtable(m) or (is_glist(m) and (is_cstring(element_type(m)) \
                or is_xml_node(element_type(m)))) or is_int(m, self.binding_data) \
                or is_boolean(m) or is_cstring(m) or is_xml_node(m):
            pass
        else:
            raise Exception('Cannot generate a Php setter %s.%s' % (c,m))
        six.print_('        %(class)s_%(name)s_set($this->_cptr, $value);' % d, file=self.fd)
        six.print_('    }', file=self.fd)
        six.print_('', file=self.fd)

    def generate_getters_and_setters(self, klass):
        for m in klass.members:
            self.generate_getter(klass, m)
            self.generate_setter(klass, m)

    def generate_methods(self, klass):
        methods = klass.methods[:]

        # first pass on methods, removing accessors
        for m in klass.methods:
            if m.rename:
                meth_name = m.rename
            else:
                meth_name = m.name
            if not ('_get_' in meth_name and len(m.args) == 1):
                continue
            methods.remove(m)
            try:
                setter_name = meth_name.replace('_get_', '_set_')
                setter = [x for x in methods if x.name == setter_name][0]
                methods.remove(setter)
            except IndexError:
                setter = None
            mname = re.match(r'lasso_.*_get_(\w+)', meth_name).group(1)
            mname = format_as_camelcase(mname)

            six.print_('    /**', file=self.fd)
            six.print_('     * @return %s' % self.get_docstring_return_type(m.return_type), file=self.fd)
            six.print_('     */', file=self.fd)
            six.print_('    protected function get_%s() {' % mname, file=self.fd)
            if self.is_object(m.return_type):
                six.print_('        $cptr = %s($this->_cptr);' % meth_name, file=self.fd)
                six.print_('        if (! is_null($cptr)) {', file=self.fd)
                six.print_('            return cptrToPhp($cptr);', file=self.fd)
                six.print_('        }', file=self.fd)
                six.print_('        return null;', file=self.fd)
            else:
                six.print_('        return %s($this->_cptr);' % meth_name, file=self.fd)
            six.print_('    }', file=self.fd)
            if setter:
                six.print_('    protected function set_%s($value) {' % mname, file=self.fd)
                if self.is_object(m.return_type):
                    six.print_('        %s($this->_cptr, $value->_cptr);' % setter.name, file=self.fd)
                else:
                    six.print_('        %s($this->_cptr, $value);' % setter.name, file=self.fd)
                six.print_('    }', file=self.fd)
            six.print_('', file=self.fd)

        # second pass on methods, real methods
        method_prefix = format_as_underscored(klass.name) + '_'
        for m in methods:
            if m.name.endswith('_new') or m.name.endswith('_new_from_dump') or \
                    m.name.endswith('_new_full'):
                continue
            if not m.name.startswith(method_prefix):
                print >> sys.stderr, 'W:', m.name, 'vs', method_prefix
                continue

            if m.rename:
                mname = m.rename
            else:
                mname = m.name
            cname = mname
            mname = mname[len(method_prefix):]
            php_args = []
            c_args = []
            outarg = None
            for arg in m.args[1:]:
                arg_type, arg_name, arg_options = arg
                arg_name = '$' + arg_name
                if is_out(arg):
                    assert not outarg
                    outarg = arg
                if arg_options.get('optional'):
                    if arg_options.get('default'):
                        defval = arg_options.get('default')
                        if defval.startswith('c:'): # constant
                            php_args.append('%s = %s' % (arg_name, defval[2:]))
                        elif defval.startswith('b:'): # boolean
                            php_args.append('%s = %s' % (arg_name, defval[2:]))
                        else:
                            print >> sys.stderr, "E: don't know what to do with %s" % defval
                            sys.exit(1)
                    else:
                        php_args.append('%s = null' % arg_name)
                else:
                    php_args.append(arg_name)
                if is_xml_node(arg) or is_boolean(arg) or is_cstring(arg) or \
                    is_int(arg, self.binding_data) or is_glist(arg) or \
                    is_hashtable(arg) or is_time_t_pointer(arg):
                    c_args.append(arg_name)
                elif is_object(arg):
                    c_args.append('%s->_cptr' % arg_name)
                else:
                    raise Exception('Does not handle argument of type: %s' % ((m, arg),))
                if is_out(arg):
                    php_args.pop()
                    php_args.append(arg_name)
                    c_args.pop()
                    c_args.append(arg_name)

            if php_args:
                php_args = ', '.join(php_args)
            else:
                php_args = ''
            if c_args:
                c_args = ', ' + ', '.join(c_args)
            else:
                c_args = ''

            if m.docstring:
                six.print_(self.generate_docstring(m, mname, 4), file=self.fd)
            six.print_('    public function %s(%s) {' % (
                    format_underscore_as_camelcase(mname), php_args), file=self.fd)
            if m.return_type == 'void':
                six.print_('        %s($this->_cptr%s);' % (cname, c_args), file=self.fd)
            elif is_rc(m.return_type):
                six.print_('        $rc = %s($this->_cptr%s);' % (cname, c_args), file=self.fd)
                six.print_('        if ($rc == 0) {', file=self.fd)
                six.print_('            return 0;', file=self.fd)
                six.print_('        } else if ($rc > 0) {', file=self.fd) # recoverable error
                six.print_('            return $rc;', file=self.fd)
                six.print_('        } else if ($rc < 0) {', file=self.fd) # unrecoverable error
                six.print_('            LassoError::throw_on_rc($rc);', file=self.fd)
                six.print_('        }', file=self.fd)
            else:
                six.print_('        return %s($this->_cptr%s);' % (cname, c_args), file=self.fd)
            six.print_('    }', file=self.fd)
            six.print_('', file=self.fd)

        six.print_('', file=self.fd)

    def generate_docstring(self, func, method_name, indent):
        docstring = func.docstring.orig_docstring
        if func.args:
            first_arg_name = func.args[0][1]
        else:
            first_arg_name = None

        def rep(s):
            type = s.group(1)[0]
            var = s.group(1)[1:]
            if type == '#': # struct
                return var
            elif type == '%': # %TRUE, %FALSE
                if var in ('TRUE', 'FALSE'):
                    return var
                print >> sys.stderr, 'W: unknown docstring thingie \'%s\' in \'%s\'' % (s.group(1), func.docstring.orig_docstring)
            elif type == '@':
                if var == first_arg_name:
                    return '$this'
                else:
                    return '$' + var
            return s.group(1)

        lines = []
        for l in docstring.splitlines():
            if l.strip() and not lines:
                continue
            lines.append(l)
        s = indent * ' ' + '/**\n'
        s += '\n'.join([indent * ' ' + ' * ' + x for x in lines[1:]])
        s += '\n' + indent * ' ' + ' */'
        regex = re.compile(r'([\#%@]\w+)', re.DOTALL)
        s = regex.sub(rep, s)
        s = s.replace('Return value: ', '@return %s ' % self.get_docstring_return_type(func.return_type))
        return s

    def get_docstring_return_type(self, return_type):
        if return_type == None:
            return ''
        elif return_type == 'gboolean':
            return 'boolean'
        elif return_type in ['int', 'gint'] + self.binding_data.enums:
            return 'int'
        elif return_type in ('char*', 'gchar*', 'const char*', 'const gchar*', 'xmlNode*'):
            return 'string'
        elif return_type in ('GList*', 'GHashTable*'):
            return 'array'
        else:
            # Objects
            return return_type.replace('*', '')

    def generate_exceptions(self):
        done_cats = []

        for exc_cat in self.binding_data.overrides.findall('exception/category'):
            cat = exc_cat.attrib.get('name')
            done_cats.append(cat)
            parent_cat = exc_cat.attrib.get('parent', '')
            six.print_('''\
/**
 * @package Lasso
 */
class Lasso%sError extends Lasso%sError {}
''' % (cat, parent_cat), file=self.fd) 

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

                six.print_('''\
/**
 * @package Lasso
 */
class Lasso%sError extends Lasso%sError {}
''' % (cat, parent_cat), file=self.fd)

            if detail not in exceptions_dict:
                six.print_('''\
/**
 * @package Lasso
 */
class Lasso%sError extends Lasso%sError {
    protected $code = %s;
}
''' % (detail, cat, c[1]), file=self.fd)
                exceptions_dict[detail] = c[1]

        six.print_('''\
/**
 * @package Lasso
 */
class LassoError extends Exception {
    private static $exceptions_dict = array(''', file=self.fd)

        for k, v in exceptions_dict.items():
            six.print_('        %s => "Lasso%sError",' % (v, k), file=self.fd)

        six.print_('''\
    );

    public static function throw_on_rc($rc) {
        $exception = self::$exceptions_dict[$rc];
        if (! class_exists($exception)) {
            $exception = "LassoError";
        }
        throw new $exception(strError($rc), $rc);
    }
}
''', file=self.fd)

    def generate_footer(self):
        six.print_('''\
?>''', file=self.fd)

