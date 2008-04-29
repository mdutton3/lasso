import re
import string

def format_as_python(var):
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

    def generate(self):
        fd = open('python/lasso.py', 'w')
        self.generate_header(fd)
        for clss in self.binding_data.structs:
            self.generate_class(clss, fd)

        fd.close()

    def generate_header(self, fd):
        print >> fd, '''\
# this file has been generated automatically; do not edit

import _lasso

_lasso.init()
'''

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

        # create properties for members
        for m in clss.members:
            mname = format_as_python(m[1])
            print >> fd, '    def get_%s(self):' % mname
            print >> fd, '        return _lasso.%s_%s_get(self._cptr)' % (
                    klassname, mname)
            print >> fd, '    def set_%s(self, value):' % mname
            print >> fd, '        _lasso.%s_%s_set(self._cptr, value)' % (
                    klassname, mname)
            print >> fd, '    %s = property(get_%s, set_%s)' % (mname, mname, mname)
            print >> fd, ''

        # first pass on methods, getting accessors
        methods = clss.methods[:]
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
        method_prefix = 'lasso_' + format_as_underscored(klassname) + '_'
        for m in methods:
            if m.name.endswith('_new') or m.name.endswith('_new_from_dump') or \
                    m.name.endswith('_new_full'):
                continue
            if not m.name.startswith(method_prefix):
                print 'W:', m.name, 'vs', method_prefix
                continue

            mname = m.name[len(method_prefix):]
            args = ', '.join([x[1] for x in m.args[1:]])
            if args:
                args = ', ' + args

            print >> fd, '    def %s(self%s):' % (format_underscore_as_py(mname), args)
            if m.return_type == 'void':
                print >> fd, '        _lasso.%s(self._cptr%s)' % (
                        m.name[6:], args)
            elif m.return_type in ('gint', 'int'):
                print >> fd, '        rc = _lasso.%s(self._cptr%s)' % (
                        m.name[6:], args)
                print >> fd, '        if rc == 0:'
                print >> fd, '            return'
                print >> fd, '        elif rc > 0:' # recoverable error
                print >> fd, '            return rc'
                print >> fd, '        elif rc < 0:' # unrecoverable error
                print >> fd, '            raise \'XXX(rc)\'' # XXX: exception hierarchy
            else:
                print >> fd, '        return _lasso.%s(self._cptr%s)' % (
                        m.name[6:], args)
            print >> fd, ''

        print >> fd, ''



