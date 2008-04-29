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

import re

import utils

class PhpCode:
    def __init__(self, binding_data, fd):
        self.binding_data = binding_data
        self.fd = fd

    def is_object(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*', 'GList*',
                'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

    def generate(self):
        self.generate_header()
        for klass in self.binding_data.structs:
            self.generate_class(klass)
        self.generate_exceptions()
        self.generate_footer()

    def generate_header(self):
        print >> self.fd, '''\
<?php

/* this file has been generated automatically; do not edit */

function cptrToPhp ($cptr) {
    $typename = lasso_get_object_typename($cptr);
    $class_name = $typename . "NoInit";
    $obj = new $class_name(); 
    if (! is_null($obj)) {
        $obj->_cptr = $cptr;
        return $obj;
    }
    return null;
}
'''

    def generate_class(self, klass):
        class_name = klass.name

        if klass.parent != 'GObject':
            inheritence = ' extends %s' % klass.parent
        else:
            inheritence = ''

        print >> self.fd, 'class %(class_name)s%(inheritence)s {' % locals()

        if klass.members or klass.methods:
            self.generate_constructors(klass)
            self.generate_getters_and_setters(klass)
            self.generate_methods(klass)

        print >> self.fd, '}'
        print >> self.fd, ''

        # Add a special class to get an object instance without initialising
        print >> self.fd, 'class %(class_name)sNoInit extends %(class_name)s {' % locals()
        print >> self.fd, '    public function __construct() {}'
        print >> self.fd, '}'
        print >> self.fd, ''

    def generate_constructors(self, klass):
        method_prefix = utils.format_as_underscored(klass.name) + '_'
        for m in self.binding_data.functions:
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
                # XXX: could check self._cptr.typename to see if it got the
                # right class type
                print >> self.fd, '    public $_cptr = null;'
                print >> self.fd, ''
                print >> self.fd, '    public function __construct(%s) {' % php_args
                print >> self.fd, '        $this->_cptr = %s(%s);' % (m.name, c_args)
                print >> self.fd, '    }'
                print >> self.fd, ''

            if m.name == method_prefix + 'new_from_dump':
                print >> self.fd, '    public static function newFromDump($dump) {'
                print >> self.fd, '        $cptr = %s($dump);' % m.name
                print >> self.fd, '        if (! is_null($cptr)) {'
                print >> self.fd, '            return cptrToPhp($cptr);'
                print >> self.fd, '        }'
                print >> self.fd, '        return null;'
                # XXX: Else throw an exception
                print >> self.fd, '    }'
                print >> self.fd, ''
            elif m.name == method_prefix + 'new_full':
                pass

    def generate_getters_and_setters(self, klass):

        # FIXME: handle objects and GLists

        # Generic getter
        print >> self.fd, '    public function __get($attr) {'
        print >> self.fd, '        $func = "get_" . $attr;'
        print >> self.fd, '        if (method_exists($this, $func)) {'
        print >> self.fd, '            return call_user_func(array($this, $func));'
        print >> self.fd, '        }'
        print >> self.fd, '        return null;'
        print >> self.fd, '    }'
        print >> self.fd, ''

        # Generic setter
        print >> self.fd, '    public function __set($attr, $value) {'
        print >> self.fd, '        $func = "set_" . $attr;'
        print >> self.fd, '        if (method_exists($this, $func)) {'
        print >> self.fd, '            call_user_func(array($this, $func), $value);'
        print >> self.fd, '        }'
        print >> self.fd, '    }'
        print >> self.fd, ''

        for m in klass.members:
            mname = utils.format_as_camelcase(m[1])
            options = m[2]
            
            # Getters
            print >> self.fd, '    protected function get_%s() {' % mname
            if self.is_object(m[0]):
                print >> self.fd, '        $cptr = %s_%s_get($this->_cptr);' % (klass.name, mname)
                print >> self.fd, '        if (! is_null($cptr)) {'
                print >> self.fd, '            return cptrToPhp($cptr);'
                print >> self.fd, '        }'
                print >> self.fd, '        return null;'
            else:
                print >> self.fd, '        return %s_%s_get($this->_cptr);' % (klass.name, mname)
            print >> self.fd, '    }'

            # Setters
            print >> self.fd, '    protected function set_%s($value) {' % mname
            print >> self.fd, '        %s_%s_set($this->_cptr, $value);' % (klass.name, mname)
            print >> self.fd, '    }'
            print >> self.fd, ''


    def generate_methods(self, klass):
        methods = klass.methods[:]

        # first pass on methods, removing accessors
        for m in klass.methods:
            if not ('_get_' in m.name and len(m.args) == 1):
                continue
            methods.remove(m)
            try:
                setter_name = m.name.replace('_get_', '_set_')
                setter = [x for x in methods if x.name == setter_name][0]
                methods.remove(setter)
            except IndexError:
                pass

        # second pass on methods, real methods
        method_prefix = utils.format_as_underscored(klass.name) + '_'
        for m in methods:
            if m.name.endswith('_new') or m.name.endswith('_new_from_dump') or \
                    m.name.endswith('_new_full'):
                continue
            if not m.name.startswith(method_prefix):
                print >> sys.stderr, 'W:', m.name, 'vs', method_prefix
                continue

            mname = m.name[len(method_prefix):]
            php_args = []
            c_args = []
            for arg in m.args[1:]:
                arg_type, arg_name, arg_options = arg
                arg_name = '$' + arg_name
                if arg_options.get('optional'):
                    if arg_options.get('default'):
                        defval = arg_options.get('default')
                        if defval.startswith('c:'): # constant
                            php_args.append('%s = %s' % (arg_name, defval[2:]))
                        else:
                            print >> sys.stderr, "E: don't know what to do with %s" % defval
                            sys.exit(1)
                    else:
                        php_args.append('%s = null' % arg_name)
                else:
                    php_args.append(arg_name)
                if arg_type in ('char*', 'const char*', 'gchar*', 'const gchar*') or \
                        arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] or \
                        arg_type in self.binding_data.enums:
                    c_args.append(arg_name)
                else:
                    c_args.append('%s._cptr' % arg_name)

            if php_args:
                php_args = ', '.join(php_args)
            else:
                php_args = ''
            if c_args:
                c_args = ', ' + ', '.join(c_args)
            else:
                c_args = ''

            print >> self.fd, '    public function %s(%s) {' % (
                    utils.format_underscore_as_camelcase(mname), php_args)
                # FIXME: add php api documentation
#            if m.docstring:
#                print >> fd, "        '''"
#                print >> fd, self.format_docstring(m, mname, 8)
#                print >> fd, "        '''"
            if m.return_type == 'void':
                print >> self.fd, '        %s($this->_cptr%s);' % (m.name, c_args)
            elif m.return_type in ('gint', 'int'):
                print >> self.fd, '        $rc = %s($this->_cptr%s);' % (m.name, c_args)
                print >> self.fd, '        if ($rc == 0) {'
                print >> self.fd, '            return 0;'
                print >> self.fd, '        } else if ($rc > 0) {' # recoverable error
                print >> self.fd, '            return $rc;'
                print >> self.fd, '        } else if ($rc < 0) {' # unrecoverable error
                print >> self.fd, '            Error::throw_on_rc($rc);'
                print >> self.fd, '        }'
            else:
                print >> self.fd, '        return %s($this->_cptr%s);' % (m.name, c_args)
            print >> self.fd, '    }'
            print >> self.fd, ''

        print >> self.fd, ''

    def generate_exceptions(self):
        done_cats = []

        for exc_cat in self.binding_data.overrides.findall('exception/category'):
            cat = exc_cat.attrib.get('name')
            done_cats.append(cat)
            parent_cat = exc_cat.attrib.get('parent', '')
            print >> self.fd, '''\
class %sError extends %sError {}
''' % (cat, parent_cat)

        exceptions_dict = {}

        for c in self.binding_data.constants:
            m = re.match(r'LASSO_(\w+)_ERROR_(.*)', c[1])
            if not m:
                continue
            cat, detail = m.groups()
            cat = cat.title().replace('_', '')
            detail = detail.title().replace('_', '')
            if not cat in done_cats:
                done_cats.append(cat)
                for exc_cat in self.binding_data.overrides.findall('exception/category'):
                    if exc_cat.attrib.get('name') == cat:
                        parent_cat = exc_cat.attrib.get('parent')
                        break
                else:
                    parent_cat = ''

                print >> self.fd, '''\
class %sError extends %sError {}
''' % (cat, parent_cat)

            if detail not in exceptions_dict:
                print >> self.fd, '''\
class %sError extends %sError {
    protected $code = %s;
}
''' % (detail, cat, c[1])
                exceptions_dict[detail] = c[1]

        print >> self.fd, '''\
class Error extends Exception {
    protected $code = null;
    protected static $exceptions_dict = array('''

        for k, v in exceptions_dict.items():
            print >> self.fd, '        %s => "%sError",' % (v, k)

        print >> self.fd, '''\
    );

    public static function throw_on_rc($rc) {
        $exception = self::$exceptions_dict[$rc];
        if (class_exists($exception)) {
            throw new $exception();
        } else {
            throw new Exception();
        }
    }

/*    public function __toString() {
        return "<" . get_class($this) . "(" . $this->code . "): " . lasso_strerror($this->code) . ">";
    } */
}
'''

    def generate_footer(self):
        print >> self.fd, '''\
?>
'''

