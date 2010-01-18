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
import string

def format_as_camelcase(var):
    '''Format an identifier name into CamelCase'''
    if '_' in var:
        return format_underscore_as_camelcase(var)
    if var[0] in string.uppercase:
        var = var[0].lower() + var[1:]
    var = re.sub(r'([a-z])(ID)([A-Z]|$)', r'\1Id\3', var) # replace standing ID by Id
    return var

def format_as_underscored(var):
    '''Format an identifier name into underscored_name'''
    def rep(s):
        return s.group(0)[0] + '_' + s.group(1).lower()
    var = re.sub(r'[a-z0-9]([A-Z])', rep, var).lower()
    var = var.replace('id_wsf2_', 'idwsf2_')
    var = var.replace('_saslresponse', '_sasl_response')
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
            print prefix * ' ' + x[prefix:]
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
            
            

