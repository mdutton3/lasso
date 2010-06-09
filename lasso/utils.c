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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "./utils.h"

/**
 * SECTION:utilities
 * @short_description: Misc functions used internally in Lasso
 * @stability: Internal
 * @include: utils.h
 */

/**
 * lasso_safe_prefix_string:
 * @str: a C string
 * @length: the maximum length of an extract of the string
 *
 * Produce a limite length safe extract of a string, for debugging purpose. Special characters are
 * replaced by their C string 'quoting'.
 *
 * Return value: a C string, of size < @length where newline, carriage returns and tabs are replaced
 * by their C quotes.
 */
gchar*
lasso_safe_prefix_string(const gchar *str, gsize length)
{
	GString *output;
	gchar *ret;
	gsize outputted = 0, i = 0;

	if (str == NULL) {
		return strdup("NULL");
	}
	output = g_string_sized_new(length);
	for (i = 0; i < length && str[i] && outputted < length; i++) {
		gchar c = 0;
		guint len;

		if ((guchar)str[i] < 128 && (guchar)str[i] > 31) {
			g_string_append_c(output, str[i]);
			outputted++;
			continue;
		}
		switch (str[i]) {
			case '\n':
				c = 'n';
				break;
			case '\t':
				c = 't';
				break;
			case '\r':
				c = 'r';
		}
		if (c) {
			if (outputted - length > 1) {
				g_string_append_c(output, '\\');
				g_string_append_c(output, c);
				outputted += 2;
				continue;
			}
		}
		if (c < 8) {
			len = 3;
		} else if (c < 64) {
			len = 4;
		} else {
			len = 5;
		}
		if (outputted - length >= len) {
			g_string_append_c(output, '\\');
			g_string_append_printf(output, "%o", (guint)str[i]);
		}
		break;
	}
	ret = output->str;
	lasso_release_gstring(output, FALSE);
	return ret;
}

/**
 * lasso_gobject_is_of_type:
 * @a: a #GObject object
 * @b: a #GType value
 *
 * Return true if object @a is of type @b.
 *
 * Return value: whether object @a is of type @b.
 */
int
lasso_gobject_is_of_type(GObject *a, GType b)
{
	GType typeid = (GType)b;

	if (a && G_IS_OBJECT(a)) {
		return G_OBJECT_TYPE(G_OBJECT(a)) == typeid ? 0 : 1;
	}
	return 1;
}

GObject*
lasso_extract_gtype_from_list(GType type, GList *list)
{
	GList *needle;

	needle = g_list_find_custom(list, (gconstpointer)type, (GCompareFunc)lasso_gobject_is_of_type);
	if (needle) {
		return needle->data;
	}
	return NULL;
}

/**
 * lasso_extract_gtype_from_list_or_new:
 * @type: a #GType
 * @list: a pointer to a #GList pointer variable
 * @create: whether to look up an object whose #GType is type, or to just create it.
 * 
 * If create is TRUE, add a new object of type @type to @list and return it.
 * Otherwise try to look up an object of type @type, and if none is found add a new one and return
 * it.
 *
 * Return value: a #GObject of type @type.
 */
GObject *
lasso_extract_gtype_from_list_or_new(GType type, GList **list, gboolean create)
{
	GObject *result = NULL;
	g_assert (list);

	if (! create) {
		result = lasso_extract_gtype_from_list(type, *list);
	}
	if (result == NULL) {
		result = g_object_new(type, NULL);
		lasso_list_add_new_gobject(*list, result);
	}
	return result;
}
