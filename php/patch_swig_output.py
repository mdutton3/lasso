#! /usr/bin/env python

"""Correct Swig output for PHP binding.

The PHP binding of Swig version 1.3.22 doest handle dynamic cast of function results well: After
the C object is dynamically casted, it creates a statically caster PHP object.

This program corrects this, by replacing:
    {
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
    {
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
        object_init_ex(obj,ptr_ce_swig_LassoXXX);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }}
and
    {
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
        object_init_ex(obj,ptr_ce_swig_LassoSamlpResponseAbstract);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }
with:
    {
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
        object_init_ex(obj,ptr_ce_swig_LassoSamlpResponseAbstract);
        add_property_zval(obj,"_cPtr",_cPtr);
        *return_value=*obj;
    }}
"""

import sys

wrap = sys.stdin.read()

i = wrap.find('    {\n        swig_type_info *ty = SWIG_TypeDynamicCast(')
while i >= 0:
    end = """
        *return_value=*obj;
    }
"""
    j = wrap.find(end, i) + len(end)
    segment = wrap[i:j]
    segment = segment.replace("""
    }
    /* Wrap this return value */
""", """
    /* Wrap this return value */
""")
    segment = segment.replace(end, """
        *return_value=*obj;
    }}
""")
    x = segment.find('object_init_ex(obj,') + len('object_init_ex(obj,')
    y = segment.find(')', x)
    segment = '%s%s%s' % (segment[:x], 'get_node_info_with_swig(ty)->php', segment[y:])
    wrap = '%s%s%s' % (wrap[:i], segment, wrap[j:])
    i = wrap.find('    {\n        swig_type_info *ty = SWIG_TypeDynamicCast(', i + len(segment))

print wrap
