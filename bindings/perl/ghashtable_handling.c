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
 * set_hash_of_strings:
 * @hash: a #GHashTable variable
 * @hv: a perl hash
 */
void
set_hash_of_strings(GHashTable **hash, HV *hv)
{
	SV *data;
	char *key;
	I32 len;

	g_hash_table_remove_all(*hash);
	hv_iterinit(hv);
	while ((data = hv_iternextsv(hv, &key, &len))) {
		if (SvTYPE(data) != SVt_PV) {
			croak("hash contains non-strings values");
		}
	}
	hv_iterinit(hv);
	while ((data = hv_iternextsv(hv, &key, &len))) {
		g_hash_table_insert(*hash, g_strndup(key, len), g_strdup(SvPV_nolen(data)));
	}
}

/**
 * set_hash_of_objects:
 * @hash: a #GHashTable variable
 * @hv: a perl hash
 */
void
set_hash_of_objects(GHashTable **hash, HV *hv)
{
	SV *data;
	char *key;
	I32 len;

	g_hash_table_remove_all(*hash);
	hv_iterinit(hv);
	while ((data = hv_iternextsv(hv, &key, &len))) {
		if (! gperl_get_object(data)) {
			croak("hash contains non-strings values");
		}
	}
	hv_iterinit(hv);
	while ((data = hv_iternextsv(hv, &key, &len))) {
		g_hash_table_insert(*hash, g_strndup(key, len), g_object_ref(data));
	}
}

static void
__ht_foreach_get_hos(gpointer key, gpointer value, gpointer user_data)
{
	HV *hv = user_data;

	(void)hv_store(hv, key, strlen(key), newSVpv(value, 0), 0);
}


/**
 * get_hash_of_strings:
 * @hash: a #GHashTable of strings
 */
HV*
get_hash_of_strings(GHashTable *hash)
{
	HV *hv;

	hv = newHV();
	g_hash_table_foreach(hash, __ht_foreach_get_hos, hv);
	return hv;
}

static void
__ht_foreach_get_hoo(gpointer key, gpointer value, gpointer user_data)
{
	HV *hv = user_data;

	(void)hv_store(hv, key, strlen(key), gperl_new_object(value, FALSE), 0);
}

/**
 * get_hash_of_objects:
 * @hash: a #GHashTable of objects
 */
HV*
get_hash_of_objects(GHashTable *hash)
{
	HV *hv;

	hv = newHV();
	g_hash_table_foreach(hash, __ht_foreach_get_hoo, hv);
	return hv;
}
