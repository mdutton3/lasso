import re
import string

def format_as_python(var):
    if '_' in var:
        return format_underscore_as_py(var)
    if var[0] in string.uppercase:
        var = var[0].lower() + var[1:]
    return var

def format_as_underscored(var):
    def rep(s):
        return s.group(0)[0] + '_' + s.group(1).lower()
    var = re.sub(r'[a-z0-9]([A-Z])', rep, var).lower()
    var = var.replace('id_wsf2_', 'idwsf2_')
    var = var.replace('_saslresponse', '_sasl_response')
    return var

def format_underscore_as_py(var):
    def rep(s):
        return s.group(1)[0].upper() + s.group(1)[1:]
    var = re.sub(r'_([A-Za-z0-9]+)', rep, var)
    return var

class PythonBinding:
    def __init__(self, binding_data):
        self.binding_data = binding_data

    def is_pygobject(self, t):
        return t not in ['char*', 'const char*', 'gchar*', 'const gchar*',
                'int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums

    def generate(self):
        fd = open('python/lasso.py', 'w')
        self.generate_header(fd)
        self.generate_constants(fd)
        for clss in self.binding_data.structs:
            self.generate_class(clss, fd)
        self.generate_footer(fd)
        fd.close()

        fd = open('python/_lasso.c', 'w')
        self.generate_wrapper(fd)
        fd.close()

    def generate_header(self, fd):
        print >> fd, '''\
# this file has been generated automatically; do not edit

import _lasso

_lasso.init()
'''

    def generate_footer(self, fd):
        print >> fd, '''
import lasso
'''

    def generate_constants(self, fd):
        print >> fd, '### Constants (both enums and defines)'
        for c in self.binding_data.constants:
            print >> fd, '%s = _lasso.%s' % (c[1][6:], c[1][6:])
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
        method_prefix = 'lasso_' + format_as_underscored(klassname) + '_'
        for m in self.binding_data.functions:
            if m.name == method_prefix + 'new':
                args = ', '.join([x[1] for x in m.args])
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
                # XXX: could check _lasso....(...)[0] to see if it got the
                # right class type
                print >> fd, '        self._cptr = _lasso.%s(%s)[1]' % (
                        m.name[6:], c_args)
                print >> fd, ''

        for m in self.binding_data.functions:
            if m.name == method_prefix + 'new_from_dump':
                print >> fd, '    @classmethod'
                print >> fd, '    def newFromDump(cls, dump):'
                print >> fd, '         obj = cls()'
                print >> fd, '         obj._cptr = _lasso.%s(dump)[1]' % m.name[6:]
                print >> fd, '         if obj._cptr is None:'
                print >> fd, '             raise "XXX"'
                print >> fd, ''
            elif m.name == method_prefix + 'new_full':
                pass

        # create properties for members
        for m in clss.members:
            mname = format_as_python(m[1])
            print >> fd, '    def get_%s(self):' % mname
            if self.is_pygobject(m[0]):
                print >> fd, '        t, cptr = _lasso.%s_%s_get(self._cptr)' % (
                        klassname, mname)
                print >> fd, '        klass = getattr(lasso, t)'
                print >> fd, '        o = klass.__new__(klass)'
                print >> fd, '        o._cptr = cptr'
                print >> fd, '        return o'
            else:
                print >> fd, '        return _lasso.%s_%s_get(self._cptr)' % (
                        klassname, mname)
            print >> fd, '    def set_%s(self, value):' % mname
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
            mname = re.match(r'lasso_.*_get_(\w+)', m.name).group(1)

            print >> fd, '    def get_%s(self):' % mname
            print >> fd, '        return _lasso.%s(self._cptr)' % m.name[6:]
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
                print 'W:', m.name, 'vs', method_prefix
                continue

            mname = m.name[len(method_prefix):]
            py_args = []
            c_args = []
            for o in m.args[1:]:
                arg_type, arg_name, arg_options = o
                if arg_options.get('optional'):
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

            print >> fd, '    def %s(self%s):' % (format_underscore_as_py(mname), py_args)
            if m.return_type == 'void':
                print >> fd, '        _lasso.%s(self._cptr%s)' % (
                        m.name[6:], c_args)
            elif m.return_type in ('gint', 'int'):
                print >> fd, '        rc = _lasso.%s(self._cptr%s)' % (
                        m.name[6:], c_args)
                print >> fd, '        if rc == 0:'
                print >> fd, '            return'
                print >> fd, '        elif rc > 0:' # recoverable error
                print >> fd, '            return rc'
                print >> fd, '        elif rc < 0:' # unrecoverable error
                print >> fd, '            raise \'XXX(rc)\'' # XXX: exception hierarchy
            else:
                print >> fd, '        return _lasso.%s(self._cptr%s)' % (
                        m.name[6:], c_args)
            print >> fd, ''

        print >> fd, ''

    def generate_wrapper(self, fd):
        print >> fd, open('lang_python_wrapper_top.c').read()
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
        print >> fd, open('lang_python_wrapper_bottom.c').read()

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
            print >> fd, '    PyDict_SetItemString(d, "%s", obj);' % c[1][6:]
            print >> fd, '    Py_DECREF(obj);'
        print >> fd, '}'
        print >> fd, ''


    def generate_member_wrapper(self, c, fd):
        klassname = c.name
        for m in c.members:
            mname = format_as_python(m[1])
            # getter
            print >> fd, '''static PyObject*
%s_%s_get(PyObject *self, PyObject *args)
{''' % (klassname[5:], mname)
            self.wrapper_list.append('%s_%s_get' % (klassname[5:], mname))

            print >> fd, '    %s return_value;' % m[0]
            print >> fd, '    PyObject* return_pyvalue;'
            print >> fd, '    PyGObjectPtr* cvt_this;'
            print >> fd, '    %s* this;' % klassname
            if self.is_pygobject(m[0]):
                print >> fd, '    PyObject* return_tuple;'
                print >> fd, '    PyObject* type_name;'

            print >> fd, '    if (! PyArg_ParseTuple(args, "O", &cvt_this)) return NULL;'
            print >> fd, '    this = (%s*)cvt_this->obj;' % klassname

            print >> fd, '    return_value = this->%s;' % m[1];

            self.return_value(fd, m[0])

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
            if m[0] in ('char*', 'const char*', 'gchar*', 'const gchar*'):
                arg_type = arg_type.replace('const ', '')
                parse_format = 's'
                parse_arg = '&value'
                print >> fd, '    %s value;' % arg_type
            elif arg_type in ['int', 'gint', 'gboolean', 'const gboolean'] + self.binding_data.enums:
                parse_format = 'i'
                parse_arg = '&value'
                print >> fd, '    %s value;' % arg_type
            else:
                parse_format = 'O'
                print >> fd, '    %s value;' % arg_type
                print >> fd, '    PyGObjectPtr *cvt_value;'
                parse_arg = '&cvt_value'

            print >> fd, '    if (! PyArg_ParseTuple(args, "O%s", &cvt_this, %s)) return NULL;' %(
                    parse_format, parse_arg)
            print >> fd, '    this = (%s*)cvt_this->obj;' % klassname

            if parse_format == 'i':
                print >> fd, '    this->%s = value;' % m[1]
            elif parse_format == 's':
                print >> fd, '    this->%s = g_strdup(value);' % m[1]
            elif parse_format == 'O':
                print >> fd, '    this->%s = (%s)g_object_ref(cvt_value->obj);' % (m[1], m[0])

            print >> fd, '    Py_INCREF(Py_None);'
            print >> fd, '    return Py_None;'
            print >> fd, '}'
            print >> fd, ''



    def return_value(self, fd, vtype):
        if vtype == 'gboolean':
            print >> fd, '    if (return_value) {'
            print >> fd, '        Py_INCREF(Py_True);'
            print >> fd, '        return Py_True;'
            print >> fd, '    } else {'
            print >> fd, '        Py_INCREF(Py_False);'
            print >> fd, '        return Py_False;'
            print >> fd, '    }'
        elif vtype in ['int', 'gint'] + self.binding_data.enums:
            print >> fd, '    return_pyvalue = PyInt_FromLong(return_value);'
            print >> fd, '    Py_INCREF(return_pyvalue);'
            print >> fd, '    return return_pyvalue;'
        elif vtype in ('char*', 'gchar*'):
            print >> fd, '    if (return_value) {'
            print >> fd, '        return_pyvalue = PyString_FromString(return_value);'
            print >> fd, '        Py_INCREF(return_pyvalue);'
            print >> fd, '        return return_pyvalue;'
            print >> fd, '    } else {'
            print >> fd, '        Py_INCREF(Py_None);'
            print >> fd, '        return Py_None;'
            print >> fd, '    }'
        else:
            # return a tuple with (object type, cPtr)
            print >> fd, '''\
    if (return_value) {
        return_pyvalue = PyGObjectPtr_New(G_OBJECT(return_value));
        Py_INCREF(return_pyvalue);
        type_name = PyString_FromString(G_OBJECT_TYPE_NAME(return_value)+5);
        Py_INCREF(type_name);
        return_tuple = PyTuple_New(2);
        PyTuple_SetItem(return_tuple, 0, type_name);
        PyTuple_SetItem(return_tuple, 1, return_pyvalue);
        return_pyvalue = return_tuple;
        Py_INCREF(return_pyvalue);
        return return_pyvalue;
    } else {
        Py_INCREF(Py_None);
        return Py_None;
    }
'''

    def generate_function_wrapper(self, m, fd):
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
            else:
                parse_tuple_format.append('O')
                parse_tuple_args.append('&cvt_%s' % arg_name)
                print >> fd, '    %s %s = NULL;' % (arg[0], arg[1])
                print >> fd, '    PyGObjectPtr *cvt_%s = NULL;' % arg_name

        if m.return_type:
            print >> fd, '    %s return_value;' % m.return_type
            print >> fd, '    PyObject* return_pyvalue;'
            if self.is_pygobject(m.return_type):
                print >> fd, '    PyObject* return_tuple;'
                print >> fd, '    PyObject* type_name;'
        print >> fd, ''

        parse_tuple_args = ', '.join(parse_tuple_args)
        if parse_tuple_args:
            parse_tuple_args = ', ' + parse_tuple_args

        print >> fd, '    if (! PyArg_ParseTuple(args, "%s"%s)) return NULL;' % (
                ''.join(parse_tuple_format), parse_tuple_args)

        for f, arg in zip(parse_tuple_format, m.args):
            if f == 'O':
                print >> fd, '    %s = (%s)cvt_%s->obj;' % (arg[1], arg[0], arg[1])

        if m.return_type:
            print >> fd, '    return_value =',
        print >> fd, '%s(%s);' % (m.name, ', '.join([x[1] for x in m.args]))

        if not m.return_type:
            print >> fd, '    Py_INCREF(Py_None);'
            print >> fd, '    return Py_None;'
        else:
            self.return_value(fd, m.return_type)
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

