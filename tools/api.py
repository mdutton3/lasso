import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__),'../bindings'))
import bindings



def main(args):
    class opt():
        pass
    options = opt()
    srcdir = args[1]
    options.srcdir = srcdir
    options.idwsf = None
    options.language = None
    options.exception_doc = None
    bindings.binding = bindings.BindingData(options)
    bindings.exclude_private = False
    bindings.parse_headers(srcdir)
    binding = bindings.binding
    d = {}
    for x in binding.constants:
        d[x[1]] = x
    for x in binding.enums:
        d[x] = None
    for x in binding.functions:
        d[x.name] = x
    for x in binding.structs:
        d[x.name] = x
    l = d.keys()
    l.sort()
    for x in l:
        if isinstance(d[x], bindings.Function):
            print d[x].return_type, " ",
            print x,
            print '(', ', '.join(map(lambda x: x[0] + ' ' + x[1], d[x].args)), ')'
        elif isinstance(d[x], bindings.Struct):
            print 'struct', x, '{ ',
            print ', '.join(map(lambda x: x[0] + ' ' + x[1], d[x].members)),
            print ' }'
        else:
            print x

if __name__ == "__main__":
    main(sys.argv)

