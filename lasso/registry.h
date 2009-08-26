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


#ifndef __REGISTRY_H__
#define __REGISTRY_H__

#include <glib.h>
#include "lasso.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define LASSO_GOBJECT_NAMESPACE "http://lasso.entrouvert.org/ns/GObject"
#define LASSO_PYTHON_NAMESPACE "http://lasso.entrouvert.org/ns/python"

typedef const char *(*LassoRegistryTranslationFunction)(const char *from_namespace, const char *from_name, const char *to_namespace);

LASSO_EXPORT gint lasso_registry_default_add_direct_mapping(const char *from_namespace,
		const char *from_name, const char *to_namespace, const char *to_name);

LASSO_EXPORT gint lasso_registry_default_add_functional_mapping(const char*from_namespace, const char *to_namespace, LassoRegistryTranslationFunction translation_function);

LASSO_EXPORT const char* lasso_registry_default_get_mapping(const char *from_namespace,
		const char *from_name, const char *to_namespace);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REGISTRY_H__ */
