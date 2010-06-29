/*
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
 *
 */

#include <perl.h>
#include <glib.h>
#include <glib-object.h>
#include <lasso/xml/xml.h>
#include <lasso/utils.h>
#include "../utils.c"

/**
 * xmlnode_to_pv:
 * @node: an xmlNode* object
 * @do_free: do we need to free the node after the conversion
 *
 * Return value: a newly allocated SV/PV or under.
 */
static SV*
xmlnode_to_pv(xmlNode *node, gboolean do_free)
{
	xmlOutputBufferPtr buf;
	SV *pestring = NULL;

	if (node == NULL) {
		return &PL_sv_undef;
	}

	buf = xmlAllocOutputBuffer(NULL);
	if (buf == NULL) {
		pestring = &PL_sv_undef;
	} else {
		xmlNodeDumpOutput(buf, NULL, node, 0, 1, NULL);
		xmlOutputBufferFlush(buf);
		if (buf->conv == NULL) {
			pestring = newSVpv((char*)buf->buffer->content, 0);
		} else {
			pestring = newSVpv((char*)buf->conv->content, 0);
		}
		xmlOutputBufferClose(buf);
	}
	if (do_free) {
		lasso_release_xml_node(node);
	}

	return pestring;
}

static xmlNode *
pv_to_xmlnode(SV *value) {
	unsigned int size;
	char *string;

	if (! SvPOK(value))
		return NULL;
	string = SvPV(value, size);
	if (! string)
		return NULL;

	return lasso_string_fragment_to_xmlnode(string, size);
}

/**
 * array_to_glist_string:
 * @array: a Perl array
 *
 * Convert a perl array to a #GList of strings.
 *
 * Return value: a newly create #GList
 */
G_GNUC_UNUSED static GList*
array_to_glist_string(AV *array)
{
	I32 len, i;
	GList *result = NULL;

	if (! array)
		return NULL;
	len = av_len(array);
	for (i=len-1; i >= 0; i--) {
		SV **sv;

		sv = av_fetch(array, i, 0);
		lasso_list_add_string(result, SvPV_nolen(*sv));
	}

	return result;
}

/**
 * array_to_glist_gobject:
 * @array: a perl array
 *
 * Convert a perl array of #GObject to a #GList of #GObject objects
 *
 * Return value: a newly created #GList of #GObject objects
 */
G_GNUC_UNUSED static GList*
array_to_glist_gobject(AV *array) {
       I32 len, i;
       GList *result = NULL;

       if (! array)
               return NULL;
       len = av_len(array);
       for (i=len-1; i >= 0; i--) {
               SV **sv;

               sv = av_fetch(array, i, 0);
               lasso_list_add_gobject(result, gperl_get_object(*sv));
       }

       return result;
}
