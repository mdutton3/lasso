/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_UTILS_H__
#define __LASSO_UTILS_H__

#include <stdio.h>
#include <glib.h>
#include <glib-object.h>
#include <xmlsec/keys.h>
#include "debug.h"
#include "backward_comp.h"
#include "xml/tools.h"
#include "logging.h"

#ifdef LASSO_DEBUG
#ifdef __GNUC__
#define lasso_check_type_equality(a,b) \
	{ \
		enum { TYPE_MISMATCH = (1 / __builtin_types_compatible_p(typeof(a), typeof(b))) }; \
	}
#else
#define lasso_check_type_equality(a,b)
#endif
#else
#define lasso_check_type_equality(a,b)
#endif

#ifdef __GNUC__
#define lasso_check_type_equality2(a,b,c) \
	{ \
		enum { TYPE_MISMATCH = (1 / (__builtin_types_compatible_p(typeof(a), typeof(b))+__builtin_types_compatible_p(typeof(a), typeof(c)))) }; \
	}
#else
#define lasso_check_type_equality2(a,b,c)
#endif

#define lasso_private_data(object) ((object)->private_data)

/**
 * lasso_ref:
 * @object: an object whose reference count must be incremented.
 *
 * Increment the reference count of an object, do not emit warning if it is NULL.
 *
 * Return value: the @object.
 */
#define lasso_ref(object) ((object) != NULL ? (g_object_ref(object), object) : NULL)

/**
 * lasso_unref:
 * @object: an object whose reference count must be decremented.
 * 
 * Decrement the reference count of an object, do not emit warnings if it is NULL.
 *
 * Return value: the @object.
 */
#define lasso_unref(object) ((object) != NULL ? (g_object_unref(object), object) : NULL)

/* Freeing */

/*
 * lasso_release_xxx are macros which ensure you do not get 'double free' errors, they first check
 * that the variable is not NULL before calling the deallocation function, and after deallocation
 * they reset the variable to NULL, preventing 'double free'.
 */
#define lasso_release(dest) \
	{ \
		if (dest) { \
			g_free(dest); dest = NULL; \
		} \
	}

#define lasso_release_full(dest, free_function) \
	{ \
		if (dest) { \
			free_function(dest); dest = NULL; \
		} \
	}

#define lasso_release_full2(dest, free_function, type) \
	{ \
		lasso_check_type_equality(dest, type); \
		if (dest) { \
			free_function(dest); dest = NULL; \
		} \
	}

#define lasso_release_gobject(dest) \
	{ \
		if (G_IS_OBJECT(dest) || dest == NULL) { \
			lasso_release_full(dest, g_object_unref); \
		} else { \
			message(G_LOG_LEVEL_CRITICAL, "Trying to unref a non GObject pointer file=%s:%u pointerbybname=%s pointer=%p", __FILE__, __LINE__, #dest, dest); \
		} \
	}

#define lasso_release_string(dest) \
	lasso_release_full(dest, g_free)

#define lasso_release_list(dest) \
	lasso_release_full2(dest, g_list_free, GList*)

#define lasso_release_slist(dest) \
	lasso_release_full2(dest, g_slist_free, GSList*)

#define lasso_release_list_of_full(dest, free_function) \
	{ \
		GList **__tmp = &(dest); \
		if (*__tmp) { \
			g_list_foreach(*__tmp, (GFunc)free_function, NULL); \
			lasso_release_list(*__tmp); \
		} \
	}

#define lasso_release_list_of_strings(dest) \
	lasso_release_list_of_full(dest, g_free)

#define lasso_release_list_of_gobjects(dest) \
	lasso_release_list_of_full(dest, g_object_unref)

#define lasso_release_list_of_xml_node(dest) \
	lasso_release_list_of_full(dest, xmlFreeNode)

#define lasso_release_list_of_xml_node_list(dest) \
	lasso_release_list_of_full(dest, xmlFreeNodeList)

#define lasso_release_list_of_sec_key(dest) \
	lasso_release_list_of_full(dest, xmlSecKeyDestroy)

#define lasso_release_xml_node(node) \
	lasso_release_full2(node, xmlFreeNode, xmlNodePtr)

#define lasso_release_xml_node_list(node) \
	lasso_release_full2(node, xmlFreeNodeList, xmlNodePtr)

#define lasso_release_doc(doc) \
	lasso_release_full2(doc, xmlFreeDoc, xmlDocPtr)

#define lasso_release_xml_string(dest) \
	lasso_release_full2(dest, xmlFree, xmlChar*)

#define lasso_release_encrypt_context(dest) \
	lasso_release_full2(dest, xmlSecEncCtxDestroy, xmlSecEncCtxPtr)

#define lasso_release_signature_context(dest) \
	lasso_release_full2(dest, xmlSecDSigCtxDestroy,xmlSecDSigCtxPtr)

#define lasso_release_key_manager(dest) \
	lasso_release_full2(dest, xmlSecKeysMngrDestroy, xmlSecKeysMngrPtr)

#define lasso_release_output_buffer(dest) \
	lasso_release_full2(dest, xmlOutputBufferClose, xmlOutputBufferPtr)

#define lasso_release_xpath_object(dest) \
	lasso_release_full2(dest, xmlXPathFreeObject, xmlXPathObjectPtr)

#define lasso_release_xpath_context(dest) \
	lasso_release_full2(dest, xmlXPathFreeContext, xmlXPathContextPtr)

#define lasso_release_xpath_job(xpathObject, xpathContext, xmlDocument) \
	lasso_release_xpath_object(xpathObject); \
	lasso_release_xpath_context(xpathContext); \
	lasso_release_doc(xmlDocument)

#define lasso_release_sec_key(dest) \
	lasso_release_full2(dest, xmlSecKeyDestroy, xmlSecKeyPtr)

#define lasso_release_ghashtable(dest) \
	lasso_release_full(dest, g_hash_table_destroy)

#define lasso_release_gstring(dest, b) \
	{ \
		GString **__tmp = &(dest); \
		if (*__tmp) {\
			g_string_free(*__tmp, (b)); \
			*__tmp = NULL; \
		} \
	}

/* Assignment and list appending */
/*
 * lasso_assign_xxx macros ensure that you dot leak previous value of assigned things, they use
 * lasso_release_xxx macros to deallocate, they also ensure proper reference counting on passed by
 * references values and proper copying on passed by value values.
 */
#define lasso_assign_string(dest,src) \
	{ \
		char *__tmp = g_strdup(src);\
		lasso_release_string(dest); \
		dest = __tmp; \
	}

#define lasso_assign_xml_string(dest,src) \
	{ \
		xmlChar *__tmp = xmlStrdup(src); \
		lasso_release_xml_string(dest); \
		dest = __tmp; \
	}

#define lasso_assign_new_string(dest,src) \
	{ \
		char *__tmp = src; \
		if (dest != __tmp) \
			lasso_release_string(dest); \
		dest = __tmp; \
	}

#define lasso_assign_gobject(dest,src) \
	{ \
		GObject *__tmp = G_OBJECT(src); \
		if (__tmp) \
			g_object_ref(__tmp); \
		lasso_release_gobject(dest); \
		dest = (void*)(__tmp); \
	}

#define lasso_assign_new_gobject(dest,src) \
	{ \
		GObject *__tmp = G_OBJECT(src); \
		if (dest != (void*)__tmp) \
			lasso_release_gobject(dest); \
		dest = (void*)(__tmp); \
	}

#define lasso_assign_xml_node(dest,src) \
	{ \
		xmlNode *__tmp = (src); \
		lasso_check_type_equality(dest, src); \
		if (dest) \
			xmlFreeNode(dest); \
		dest = xmlCopyNode(__tmp, 1); \
	}

#define lasso_assign_new_xml_node(dest,src) \
	{ \
		xmlNode *__tmp = (src); \
		lasso_check_type_equality(dest, src); \
		if (dest) \
			xmlFreeNode(dest); \
		dest = __tmp; \
	}

#define lasso_assign_xml_node_list(dest,src) \
	{ \
		xmlNode *__tmp = (src); \
		lasso_check_type_equality(dest, src); \
		if (dest) \
			xmlFreeNode(dest); \
		dest = xmlCopyNodeList(__tmp); \
	}

#define lasso_assign_new_xml_node_list(dest,src) \
	lasso_assign_new_xml(dest, src)

#define lasso_assign_list(dest, src) \
	{ \
		GList **__tmp = &(dest); \
		if (*__tmp) \
			g_list_free(*__tmp); \
		*__tmp = g_list_copy((src)); \
	}

#define lasso_assign_new_list_of_gobjects(dest, src) \
	{ \
		GList *__tmp = (src); \
		lasso_release_list_of_gobjects(dest); \
		dest = (GList*)__tmp; \
	}

#define lasso_assign_new_list_of_strings(dest, src) \
	{ \
		GList *__tmp = (src); \
		lasso_release_list_of_strings(dest); \
		dest = (GList*)__tmp; \
	}

#define lasso_assign_new_list_of_xml_node(dest, src) \
	{ \
		GList *__tmp = (src); \
		lasso_release_list_of_xml_node(dest); \
		dest = (GList*)__tmp; \
	}

#define lasso_assign_list_of_gobjects(dest, src) \
	{ \
		GList *__tmp = (src); \
		lasso_release_list_of_gobjects(dest); \
		dest = g_list_copy(__tmp); \
		for (;__tmp != NULL; __tmp = g_list_next(__tmp)) { \
			if (G_IS_OBJECT(__tmp->data)) { \
				g_object_ref(__tmp->data); \
			} \
		} \
	}

#define lasso_assign_list_of_strings(dest, src) \
	{ \
		GList *__tmp = src; \
		GList *__iter_dest; \
		lasso_release_list_of_strings(dest); \
		dest = g_list_copy(__tmp); \
		for (__iter_dest = dest ; __iter_dest != NULL ; __iter_dest = g_list_next(__iter_dest)) { \
			__iter_dest->data = g_strdup(__iter_dest->data); \
		} \
	}

#define lasso_assign_new_sec_key(dest, src) \
	{ \
		xmlSecKey *__tmp = (src); \
		if (dest) \
			lasso_release_sec_key(dest); \
		dest = __tmp; \
	}

#define lasso_assign_sec_key(dest, src) \
	{ \
		xmlSecKey *__tmp = xmlSecKeyDuplicate(src); \
		if (dest) \
			lasso_release_sec_key(dest); \
		dest = __tmp; \
	}

/* List appending */

/* lasso_list_add_xxx macros, simplify code around list manipulation (g_list_append needs to be
 * used like this 'l = g_list_appen(l, value)' ) and ensure proper reference count or copying of
 * values.
 */
#define lasso_list_add(dest, src) \
	{ \
		lasso_check_type_equality((src), void*); \
		dest = g_list_append(dest, (src)); \
	}

#define lasso_list_add_non_null(dest, src) \
	{ \
		void *__tmp_non_null_src = (src); \
		if (__tmp_non_null_src != NULL) { \
			dest = g_list_append(dest, __tmp_non_null_src); \
		} else { \
			message(G_LOG_LEVEL_CRITICAL, "Adding a NULL value to a non-NULL content list: dest=%s src=%s", #dest, #src); \
		} \
	}

#define lasso_list_add_string(dest, src) \
	{ \
		lasso_list_add_non_null(dest, g_strdup(src));\
	}

#define lasso_list_add_new_string(dest, src) \
	{ \
		gchar *__tmp = src; \
		lasso_list_add_non_null(dest, __tmp); \
	}

#define lasso_list_add_xml_string(dest, src) \
	{\
		xmlChar *__tmp_src = (src);\
		lasso_list_add_non_null(dest, (void*)g_strdup((char*)__tmp_src));\
	}

#define lasso_list_add_gobject(dest, src) \
	{ \
		void *__tmp_src = (src); \
		if (G_IS_OBJECT(__tmp_src)) { \
			dest = g_list_append(dest, g_object_ref(__tmp_src)); \
		} else { \
			message(G_LOG_LEVEL_CRITICAL, "Trying to add to a GList* a non GObject pointer dest=%s src=%s", #dest, #src); \
		} \
	}

#define lasso_list_add_new_gobject(dest, src) \
	{ \
		void *__tmp_src = (src); \
		if (G_IS_OBJECT(__tmp_src)) { \
			dest = g_list_append(dest, __tmp_src); \
		} else { \
			message(G_LOG_LEVEL_CRITICAL, "Trying to add to a GList* a non GObject pointer dest=%s src=%s", #dest, #src); \
		} \
	}

#define lasso_list_add_xml_node(dest, src) \
	{ \
		xmlNode *__tmp_src = xmlCopyNode(src, 1); \
		lasso_list_add_non_null(dest, __tmp_src); \
	}

#define lasso_list_add_new_xml_node(dest, src) \
	{ \
		xmlNode *__tmp_src = src; \
		lasso_list_add_non_null(dest, __tmp_src); \
	}

#define lasso_list_add_xml_node_list(dest, src) \
	{ \
		xmlNode *__tmp_src = xmlCopyNodeList(src); \
		lasso_list_add_non_null(dest, __tmp_src); \
	}

#define lasso_list_add_new_xml_node_list(dest, src) \
	lasso_list_add_new_xml_node(dest, src)

#define lasso_list_add_gstrv(dest, src) \
	{ \
		GList **__tmp_dest = &(dest); \
		const char **__iter = (const char**)(src); \
		while (__iter && *__iter) { \
			lasso_list_add_string(*__tmp_dest, *__iter); \
		} \
	}

#define lasso_list_add_new_sec_key(dest, src) \
	{ \
		xmlSecKey *__tmp_src = (src); \
		lasso_list_add_non_null(dest, __tmp_src); \
	}

/* List element removal */
#define lasso_list_remove_gobject(list, gobject) \
	do { void *__tmp = gobject; GList **__tmp_list = &(list); \
		*__tmp_list = g_list_remove(*__tmp_list, __tmp); \
		lasso_unref(__tmp); } while(0)

/* List element membership */
#define lasso_is_in_list_of_strings(list, item) \
	g_list_find_custom(list, item, (GCompareFunc)g_strcmp0) == NULL ? FALSE : TRUE


/* Pointer ownership transfer */

/* lasso_transfer_xxx macros are like lasso_assign_xxx but they do not increment reference count or
 * copy the source value, instead they steal the value (and set the source to NULL, preventing stale
 * references).
 */
#define lasso_transfer_full(dest, src, kind) \
	{\
		lasso_release_##kind((dest)); \
		lasso_check_type_equality(dest, src); \
		(dest) = (void*)(src); \
		(src) = NULL; \
	}

#define lasso_transfer_xpath_object(dest, src) \
	lasso_transfer_full(dest, src, xpath_object)

#define lasso_transfer_string(dest, src) \
	lasso_transfer_full(dest, src, string)

#define lasso_transfer_gobject(dest, src) \
	lasso_transfer_full(dest, src, gobject)

#define lasso_transfer_xml_node(dest, src) \
	lasso_transfer_full(dest, src, xml_node)

/* Node extraction */
#define lasso_extract_node_or_fail(to, from, kind, error) \
	{\
		void *__tmp = (from); \
		if (LASSO_IS_##kind(__tmp)) { \
			to = LASSO_##kind(__tmp); \
		} else { \
			rc = error; \
			goto cleanup; \
		}\
	}

/* Bad param handling */
#define lasso_return_val_if_invalid_param(kind, name, val) \
	g_return_val_if_fail(LASSO_IS_##kind(name), val)

#define lasso_bad_param(kind, name) \
	lasso_return_val_if_invalid_param(kind, name, \
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

#define lasso_null_param(name) \
	g_return_val_if_fail(name != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

/**
 * lasso_check_non_empty_string:
 * @str: a char pointer
 *
 * Check that @str is non-NULL and not empty, otherwise jump to cleanup and return
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ.
 */
#define lasso_check_non_empty_string(str) \
	goto_cleanup_if_fail_with_rc(! lasso_strisempty(str), \
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

/*
 * We extensively use goto operator but in a formalized way, i.e. only for error checking code
 * paths.
 *
 * The next macros goto_cleanup_xxxx encapsulate idioms used in lasso, like checking for a condition
 * or setting the return code which must be called 'rc' and be of an 'int' type.
 */

/*
 * The following macros are made to create some formalism for function's cleanup code.
 *
 * The exit label should be called 'cleanup'. And for functions returning an integer error code, the
 * error code should be named 'rc' and 'return rc;' should be the last statement of the function.
 */

/**
 * goto_cleanup_with_rc:
 * @rc_value: integer return value
 *
 * This macro jump to the 'cleanup' label and set the return value to @rc_value.
 *
 */
#define goto_cleanup_with_rc(rc_value) \
	do {\
		rc = (rc_value); \
		goto cleanup; \
	} while(0);

/**
 * goto_cleanup_if_fail:
 * @condition: a boolean condition
 *
 * Jump to the 'cleanup' label if the @condition is FALSE.
 *
 */
#define goto_cleanup_if_fail(condition) \
	{\
		if (! (condition) ) {\
			goto cleanup; \
		} \
	}

/**
 * goto_cleanup_if_fail_with_rc:
 * @condition: a boolean condition
 * @rc_value: integer return value
 *
 * Jump to the 'cleanup' label if the @condition is FALSE and set the return value to
 * @rc_value.
 *
 */
#define goto_cleanup_if_fail_with_rc(condition, rc_value) \
	{\
		if (! (condition) ) {\
			rc = (rc_value); \
			goto cleanup; \
		} \
	}

/**
 * goto_cleanup_if_fail_with_rc_with_warning:
 * @condition: a boolean condition
 * @rc_value: integer return value
 *
 * Jump to the 'cleanup' label if the @condition is FALSE and set the return value to
 * @rc_value. Also emit a warning, showing the condition and the return value.
 *
 */
#define goto_cleanup_if_fail_with_rc_with_warning(condition, rc_value) \
	{\
		if (! (condition) ) {\
			message(G_LOG_LEVEL_WARNING, "%s failed, returning %s", #condition, #rc_value);\
			rc = (rc_value); \
			goto cleanup; \
		} \
	}

/**
 * check_good_rc:
 * @what: a call to a function returning a lasso error code
 *
 * Check if return code is 0, if not store it in rc and jump to cleanup label.
 */
#define lasso_check_good_rc(what) \
	{ \
		int __rc = (what);\
		goto_cleanup_if_fail_with_rc(__rc == 0, __rc); \
	}

#define lasso_mem_debug(who, what, where) \
	{ \
		if (lasso_flag_memory_debug) \
		fprintf(stderr, "  freeing %s/%s (at %p)\n", who, what, (void*)where); \
	}

/**
 * lasso_foreach:
 * @_iter: a #GList variable, which will server to traverse @_list
 * @_list: a #GList value, which we will traverse
 *
 * Traverse a #GList list using 'for' construct. It must be followed by a block or a statement.
 */
#define lasso_foreach(_iter, _list) \
	for (_iter = (_list); _iter; _iter = g_list_next(_iter))

/**
 * lasso_foreach_full_begin:
 * @_type: the type of the variable @_data
 * @_data: the name of the variable to define to store data values
 * @_iter: the name of the variable to define to store the iterator
 * @_list: the GList* to iterate
 *
 * Traverse a GList* @_list, using @_iter as iteration variable extract data field to variable
 * @_data of type @_type.
 */
#define lasso_foreach_full_begin(_type, _data, _iter, _list) \
	{ \
		_type _data = NULL; \
		GList *_iter = NULL; \
		for (_iter = (_list); _iter && ((_data = _iter->data), 1); _iter = g_list_next(_iter)) \
		{

#define lasso_foreach_full_end() \
				} }

/**
 * lasso_list_get_first_child:
 * @list:(allowed-none): a #GList node or NULL.
 *
 * Return the first child in a list, or NULL.
 */
#define lasso_list_get_first_child(list) \
	((list) ? (list)->data : NULL)

/* Get a printable extract for error messages */
char* lasso_safe_prefix_string(const char *str, gsize length);

int lasso_gobject_is_of_type(GObject *a, GType b);

GObject *lasso_extract_gtype_from_list(GType type, GList *list);

GObject * lasso_extract_gtype_from_list_or_new(GType type, GList **list, gboolean create);

/* Get first node of this type in a list */
/* ex: lasso_extract_node (LassoNode, LASSO_TYPE_NODE, list) */
#define lasso_extract_gobject_from_list(type, gobjecttype, list) \
	((type*) lasso_extract_gtype_from_list(gobjecttype, list))

/*
 * Simplify simple accessors argument checking.
 *
 */
#define lasso_return_val_if_fail(assertion, value) \
	if (!(assertion)) return (value);

#define lasso_return_null_if_fail(assertion) \
	lasso_return_val_if_fail(assertion, NULL)

#define lasso_return_if_fail(assertion) \
	if (!(assertion)) return;

#define lasso_trace(args...) \
	if (lasso_flag_memory_debug) { \
		fprintf(stderr, ## args); \
	}

/* Lasso string data helpers */
inline static gboolean
lasso_strisequal(const char *a, const char *b) {
	return (g_strcmp0(a,b) == 0);
}
inline static gboolean
lasso_strisnotequal(const char *a, const char *b) {
	return ! lasso_strisequal(a,b);
}
inline static gboolean
lasso_strisempty(const char *str) {
	return ((str) == NULL || (str)[0] == '\0');
}
inline static gboolean
lasso_xmlstrisnotequal(const xmlChar *a, const xmlChar *b) {
	return lasso_strisnotequal((char*)a, (char*)b);
}

/**
 * lasso_crypto_memequal:
 * @a: first buffer
 * @b: second buffer
 * @l: common length
 *
 * Compare two buffers, preventing timing attacks.
 */
static inline gboolean
lasso_crypto_memequal(void *a, void *b, unsigned int l)
{
	unsigned char *x = a, *y = b;
	gboolean result = TRUE;

	for (;l;l--, x++, y++) {
		result = result && (*x == *y);
	}
	return result;
}

#endif /* __LASSO_UTILS_H__ */
