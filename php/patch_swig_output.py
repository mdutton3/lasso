#! /usr/bin/env python

"""Correct Swig output for PHP binding.

The PHP binding of Swig version 1.3.22 has several bugs:

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
begin = """
    {
        swig_type_info *ty = SWIG_TypeDynamicCast("""
end = """
        *return_value=*obj;
    }}
"""
i = wrap.find(begin)
while i >= 0:
    j = wrap.find(end, i) + len(end)
    segment = wrap[i:j]
    x = segment.find('object_init_ex(obj,') + len('object_init_ex(obj,')
    y = segment.find(')', x)
    segment = '%s%s%s' % (segment[:x], 'get_node_info_with_swig(ty)->php', segment[y:])
    wrap = '%s%s%s' % (wrap[:i], segment, wrap[j:])
    i = wrap.find(begin, i + len(segment))

print wrap
