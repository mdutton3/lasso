#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id$
#
# SWIG based PHP binding for Lasso Library
#
# Copyright (C) 2004, 2005 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file.
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


"""Correct SWIG output for PHP binding.

The PHP binding of SWIG version 1.3.22 has several bugs:

(1) It wraps NULL pointers into non NULL PHP objects.

(2) It doesn't handle dynamic cast of function results well: After the C object is dynamically
    casted, it creates a statically casted PHP object.

This program corrects (1) and (2), by replacing things like:
    if (!result) {
        ZVAL_NULL(return_value);
    } else {
        swig_type_info *ty = SWIG_TypeDynamicCast(SWIGTYPE_p_LassoXXX, (void **) &result);
        SWIG_SetPointerZval(return_value, (void *)result, ty, 1);
    }

    /* Wrap this return value */
    if (this_ptr) {
        /* NATIVE Constructor, use this_ptr */
        zval *_cPtr; MAKE_STD_ZVAL(_cPtr);
        *_cPtr = *return_value;
        INIT_ZVAL(*return_value);
        add_property_zval(this_ptr,"_cPtr",_cPtr);
    } else if (! this_ptr) {
        /* ALTERNATIVE Constructor, make an object wrapper */
        zval *obj, *_cPtr;
        MAKE_STD_ZVAL(obj);
        MAKE_STD_ZVAL(_cPtr);
        *_cPtr = *return_value;
        INIT_ZVAL(*return_value);
        object_init_ex(obj,ptr_ce_swig_LassoXXX);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }
with:
    if (!result) {
        ZVAL_NULL(return_value);
    } else {
        swig_type_info *ty = SWIG_TypeDynamicCast(SWIGTYPE_p_LassoXXX, (void **) &result);
        SWIG_SetPointerZval(return_value, (void *)result, ty, 1);
    /* Wrap this return value */
    if (this_ptr) {
        /* NATIVE Constructor, use this_ptr */
        zval *_cPtr; MAKE_STD_ZVAL(_cPtr);
        *_cPtr = *return_value;
        INIT_ZVAL(*return_value);
        add_property_zval(this_ptr,"_cPtr",_cPtr);
    } else if (! this_ptr) {
        /* ALTERNATIVE Constructor, make an object wrapper */
        zval *obj, *_cPtr;
        MAKE_STD_ZVAL(obj);
        MAKE_STD_ZVAL(_cPtr);
        *_cPtr = *return_value;
        INIT_ZVAL(*return_value);
        object_init_ex(obj,get_node_info_with_swig(ty)->php);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }}
and
    if (!result) {
        ZVAL_NULL(return_value);
    } else {
        swig_type_info *ty = SWIG_TypeDynamicCast(SWIGTYPE_p_LassoXXX, (void **) &result);
        SWIG_SetPointerZval(return_value, (void *)result, ty, 0);
    }

    /* Wrap this return value */
    {
        /* ALTERNATIVE Constructor, make an object wrapper */
        zval *obj, *_cPtr;
        MAKE_STD_ZVAL(obj);
        MAKE_STD_ZVAL(_cPtr);
        *_cPtr = *return_value;
        INIT_ZVAL(*return_value);
        object_init_ex(obj,ptr_ce_swig_LassoXXX);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }
with:
    if (!result) {
        ZVAL_NULL(return_value);
    } else {
        swig_type_info *ty = SWIG_TypeDynamicCast(SWIGTYPE_p_LassoXXX, (void **) &result);
        SWIG_SetPointerZval(return_value, (void *)result, ty, 0);
    /* Wrap this return value */
    {
        /* ALTERNATIVE Constructor, make an object wrapper */
        zval *obj, *_cPtr;
        MAKE_STD_ZVAL(obj);
        MAKE_STD_ZVAL(_cPtr);
        *_cPtr = *return_value;
        INIT_ZVAL(*return_value);
        object_init_ex(obj,get_node_info_with_swig(ty)->php);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }}
"""

import sys

wrap = sys.stdin.read()

# (1)
begin = """
    }
    
    /* Wrap this return value */
"""
end = """
        *return_value=*obj;
    }
"""
i = wrap.find(begin)
while i >= 0:
    j = wrap.find(end, i) + len(end)
    segment = wrap[i:j]
    segment = segment.replace(begin, """
    /* Wrap this return value */
""")
    segment = segment.replace(end, """
        *return_value=*obj;
    }}
""")
    wrap = '%s%s%s' % (wrap[:i], segment, wrap[j:])
    i = wrap.find(begin, i + len(segment))

# (2)
begin = 'swig_type_info *ty = SWIG_TypeDynamicCast('
end = """
        *return_value=*obj;
    }}
"""
i = wrap.find(begin)
while i >= 0:
    j = wrap.find(end, i) + len(end)
    if j < len(end): # bails out if not found
        break
    segment = wrap[i:j]
    x = segment.find('object_init_ex(obj,') + len('object_init_ex(obj,')
    y = segment.find(')', x)
    segment = '%s%s%s' % (segment[:x], 'get_node_info_with_swig(ty)->php', segment[y:])
    wrap = '%s%s%s' % (wrap[:i], segment, wrap[j:])
    i = wrap.find(begin, i + len(segment))

print wrap
