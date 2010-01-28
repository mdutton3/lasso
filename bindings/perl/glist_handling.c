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

/**
 * xmlnode_to_pv:
 * @node: an xmlNode* object
 * @do_free: do we need to free the node after the conversion
 *
 * Return value: a newly allocated SV/PV or under.
 */
SV*
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

xmlNode *pv_to_xmlnode(SV *value) {
	char *string = SvPV_nolen(value);
	xmlDoc *doc;
	xmlNode *node = NULL;

	if (! string)
		return NULL;

	doc = xmlReadDoc(BAD_CAST string, NULL, NULL, XML_PARSE_NONET);
	if (! doc)
		return NULL;
	lasso_assign_xml_node(node, xmlDocGetRootElement(doc));
	lasso_release_doc(doc);

	return node;
}

/**
 * glist_string_to_array:
 * @list: a GList* of strings
 * @do_free: wheter to free the list after the transformation
 *
 * Convert a #GList of strings to a Perl array of strings.
 *
 * Return value: a newly created perl array
 */
AV*
glist_string_to_array(GList *list, gboolean do_free)
{
	AV *array;

	array = newAV();

	while (list) {
		SV *sv;
		sv = newSVpv((char*)list->data, 0);
		if (! sv)
			sv = &PL_sv_undef;
		av_push(array, sv);
		list = list->next;
	}

	if (do_free)
		lasso_release_list_of_strings(list);

	return array;
}

/**
 * array_to_glist_string:
 * @array: a Perl array
 *
 * Convert a perl array to a #GList of strings.
 *
 * Return value: a newly create #GList
 */
GList*
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
 * glist_gobject_to_array:
 * @list: a #GList of #GObject objects
 * @do_free: wheter to free the list after the conversion
 *
 * Convert a #GList of #GObject objects to a perl array.
 *
 * Return value: a newly created perl array
 */
AV*
glist_gobject_to_array(GList *list, gboolean do_free)
{
	AV *array;

	array = newAV();
	while (list) {
		SV *sv;
		sv = gperl_new_object((GObject*)list->data, FALSE);
		if (! sv)
			sv = &PL_sv_undef;
		av_push(array, sv);
		list = list->next;
	}

	if (do_free)
		lasso_release_list_of_gobjects(list);

	return array;
}

/**
 * array_to_glist_gobject:
 * @array: a perl array
 *
 * Convert a perl array of #GObject to a #GList of #GObject objects
 *
 * Return value: a newly created #GList of #GObject objects
 */
GList*
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

/**
 * glist_xmlnode_to_array:
 * @list: a #GList of #xmlNode
 * @do_free: whether to free the list after the conversion
 *
 * Convert a #GList of #xmlNode structures to a perl array of strings.
 *
 * Return value: a newly created Perl array */
AV*
glist_xmlnode_to_array(GList *list, gboolean do_free)
{
	AV *array;

	array = newAV();
	while (list) {
		SV *sv = xmlnode_to_pv((xmlNode*)list->data, FALSE);
		if (! sv)
			sv = &PL_sv_undef;
		av_push(array, sv);
		list = list->next;
	}

	if (do_free)
		lasso_release_list_of_xml_node(list);

	return array;
}

/**
 * array_to_glist_xmlnode:
 * @array: a perl array
 *
 * Convert a perl array of strings to a #GList of #xmlNode structures.
 *
 * Return value: a newly created #GList of #xmlNode structures.
 */
GList*
array_to_glist_xmlnode(AV *array) {
	I32 len, i;
	GList *result = NULL;

	if (! array)
		return NULL;
	len = av_len(array);
	for (i=len-1; i >= 0; i--) {
		SV **sv;

		sv = av_fetch(array, i, 0);
		lasso_list_add_new_xml_node(result, pv_to_xmlnode(*sv));
	}

	return result;
}