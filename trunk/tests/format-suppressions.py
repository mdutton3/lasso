import re

valgrind_log = open('log','r').read()

inblock = False
l = 0
i = 0
keep = dict()

limit_re = r'type'

for line in valgrind_log.splitlines():
    if line.startswith('{'):
        inblock = True
        block = []
        continue
    if line.startswith('}'):
        inblock = False
        l = 0
        i += 1
        ok = False
        name = ""
        for x in block[2:]:
            name = name + x
            if re.search(limit_re, x):
                ok = True
                break
        if ok:
            keep[name] = block
        continue
    if inblock:
        block.append(line)
i = 43
for x in keep:
    block = keep[x]
    print "{"
    print "   suppression", i
    for x in block[1:]:
        print x
        if re.search(limit_re, x):
            break
    print '}'
    i += 1
