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
 *
 */

#ifndef BACKWARD_COMP_H
#define BACKWARD_COMP_H 1

/* This file contains re-implementations of functions which only exists in recent version of our
 * dependencies, like GLib, OpenSSL or libxml.
 */

/* GLIB backward-compatibility */
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 16)
#include <string.h>

static inline int g_strcmp0(const char *str1, const char *str2) {
	if (str1 == NULL && str2 == NULL) {
		return 0;
	}
	if (str1 == NULL) {
		return -1;
	}
	if (str2 == NULL) {
		return 1;
	}
	return strcmp(str1, str2);
}
#endif

#endif /* BACKWARD_COMP_H */
