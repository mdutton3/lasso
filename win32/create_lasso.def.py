#! /usr/bin/env python

# usage:
#  ./create_lasso.def.py /path/to/liblasso.so > lasso.def

import sys, commands

cmd = "nm -B " + sys.argv[1]
output = commands.getoutput(cmd)
lines = output.split("\n")

print "LIBRARY liblasso.dll\n"
print "DESCRIPTION \"Free implementation of the Liberty Alliance specifications.\"\n"
print "EXPORTS\n"

i = 0
# Functions exports
print "; Functions exports"
for line in lines:
    infos = line.split(" ")
    if infos[1] == "T" and infos[2][0] != "_":
        print "    " + infos[2]
        i = i + 1
# Var exports
print "\n; Var exports"
for line in lines:
    infos = line.split(" ")
    if infos[1] == "R" and infos[2][0] != "_":
        print "    " + infos[2]
        i = i + 1
#print i
