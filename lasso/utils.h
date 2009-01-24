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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_UTILS_H__
#define __LASSO_UTILS_H__

#include <glib.h>

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

/* Assignment and list appending */
#define lasso_assign_string(dest,src) \
	{ \
		void *t = g_strdup(src);\
		if (dest) g_free(dest); \
		dest = t; \
	}

#define lasso_assign_new_string(dest,src) \
	{ \
		if (dest) g_free(dest); \
		dest = src; \
	}

#define lasso_assign_gobject(dest,src) \
	{ \
		lasso_check_type_equality(dest, src); \
		if (src) \
			g_object_ref(src); \
		if (dest) \
			g_object_unref(dest); \
		dest = (void*)(src); \
	}

#define lasso_assign_new_gobject(dest,src) \
	{ \
		lasso_check_type_equality(dest, src); \
		if (dest) \
			g_object_unref(dest); \
		dest = (void*)(src); \
	}

#define lasso_assign_node(dest,src) \
	{ \
		lasso_check_type_equality(dest, src); \
		if (dest) \
			xmlFreeNode(dest); \
		dest = xmlCopyNode(src, 1); \
	}

#define lasso_list_add(dest, src) \
	{ \
		lasso_check_type_equality(src, void*); \
		dest = g_list_append(dest, src); \
	}

#define lasso_list_add_non_null(dest, src) \
	{ \
		lasso_check_type_equality(src, void*); \
		if (src != NULL) { \
			dest = g_list_append(dest, src); \
		} else { \
			g_critical("Adding a NULL value to a non-NULL content list: dest=%s src=%s", #dest, #src); \
		} \
	}

#define lasso_list_add_string(dest, src) \
	{ \
		lasso_check_type_equality(dest, GList*); \
		lasso_check_type_equality(src, gchar*); \
		(dest) = g_list_append((dest), g_strdup(src));\
	}

#define lasso_list_add_xml_string(dest, src) \
	{ \
		lasso_check_type_equality(dest, GList*); \
		lasso_check_type_equality(src, xmlChar*); \
		(dest) = g_list_append((dest), g_strdup((char*)src));\
	}

#define lasso_list_add_gobject(dest, src) \
	{ \
		if (G_IS_OBJECT(src)) { \
			dest = g_list_append(dest, g_object_ref(src)); \
		} else { \
			g_critical("Trying to add to a GList* a non GObject pointer dest=%s src=%s", #dest, #src); \
		} \
	}

#define lasso_list_add_new_gobject(dest, src) \
	{ \
		if (G_IS_OBJECT(src)) { \
			dest = g_list_append(dest, src); \
		} else { \
			g_critical("Trying to add to a GList* a non GObject pointer dest=%s src=%s", #dest, #src); \
		} \
	}

/* Freeing */
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
			g_critical("Trying to unref a non GObject pointer dest=%s", #dest); \
		} \
	}

#define lasso_release_string(dest) \
	lasso_release_full(dest, g_free)

#define lasso_release_list(dest) \
	lasso_release_full2(dest, g_list_free, GList*)

#define lasso_release_list_of_full(dest, free_function) \
	{ \
		if (dest) { \
			g_list_foreach(dest, (GFunc)free_function, NULL); \
			lasso_release_list(dest); \
		} \
	}

#define lasso_release_list_of_strings(dest) \
	lasso_release_list_of_full(dest, g_free)

#define lasso_release_list_of_gobjects(dest) \
	lasso_release_list_of_full(dest, g_object_unref)

#define lasso_unlink_and_release_node(node) \
	lasso_release_list_of_full(dest, xmlFreeNode)

#define lasso_release_node(node) \
	lasso_release_full2(node, xmlFreeNode, xmlNodePtr)

#define lasso_release_doc(doc) \
	lasso_release_full2(doc, xmlFreeDoc, xmlDocPtr)

#define lasso_release_xmlchar(dest) \
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

/* Bad param handling */
#define lasso_return_val_if_invalid_param(kind, name, val) \
	g_return_val_if_fail(LASSO_IS_##kind(name), val)

#define lasso_bad_param(kind, name) \
	lasso_return_val_if_invalid_param(kind, name, \
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

#define lasso_null_param(name) \
	g_return_val_if_fail(name != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

#define goto_exit_with_rc(rc_value) \
	{\
		rc = (rc_value); \
		goto exit; \
	}

#define goto_exit_if_fail(condition, rc_value) \
	{\
		if (! (condition) ) {\
			rc = (rc_value); \
			goto exit; \
		} \
	}

#define goto_exit_if_fail_with_warning(condition, rc_value) \
	{\
		if (! (condition) ) {\
			g_warning("%s %s", __STRING(condition), __STRING(rc_value));\
			rc = (rc_value); \
			goto exit; \
		} \
	}

/* Declare type of element in a container */
#define OFTYPE(x)

/* Get a printable extract for error messages */
char* lasso_safe_prefix_string(const char *str, gsize length);

#endif /* __LASSO_UTILS_H__ */
