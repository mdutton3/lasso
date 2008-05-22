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

/* Assignment and list appending */
#define g_assign_string(dest,src) { void *t = g_strdup(src); if (dest) g_free(dest); dest = t; }
#define g_assign_new_string(dest,src) { if (dest) g_free(dest); dest = src; }
#define g_assign_gobject(dest,src) { if (src) g_object_ref(src); if (dest) g_object_unref(dest); dest = (void*)(src); }
#define g_assign_new_gobject(dest,src) { if (dest) g_object_unref(dest); dest = (void*)(src); }
#define g_list_add_gobject(dest, src) { dest = g_list_append(dest, g_object_ref(src)); }
#define g_list_add_new_gobject(dest, src) { dest = g_list_append(dest, src); }
#define g_list_add(dest, src) { dest = g_list_append(dest, src); }
#define g_list_add_fast(dest, src) { dest = g_list_prepend(dest, src); }

/* Freeing */
#define g_release(dest) { if (dest) { g_free(dest); dest = NULL; } }
#define g_release_gobject(dest) { if (dest) { g_object_unref(dest); dest = NULL; } }
#define g_release_list_of_strings(dest) { if (dest) { g_list_foreach(dest, (GFunc)g_free); g_list_free(dest); dest = NULL; } }
#define g_release_list_of_gobjects(dest) { if (dest) { g_list_foreach(dest, (GFunc)g_object_unref); g_list_free(dest); dest = NULL; } }
#define g_release_list(dest) { if (dest) { g_list_free(dest); dest = NULL; } }
#define g_unlink_and_release_node(node) { if (node) { xmlUnlinkNode(node); xmlFreeNode(node); node = NULL; } }

/* Bad param handling */
#define g_return_val_if_invalid_param(kind, name, val) \
	g_return_val_if_fail(LASSO_IS_##kind(name), val)

#endif /* __LASSO_UTILS_H__ */
