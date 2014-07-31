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

#ifndef __LASSO_DEBUG_H__
#define __LASSO_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include "export.h"

LASSO_EXPORT extern gboolean lasso_flag_verify_signature;
LASSO_EXPORT extern gboolean lasso_flag_memory_debug;
LASSO_EXPORT extern gboolean lasso_flag_strict_checking;
LASSO_EXPORT extern gboolean lasso_flag_add_signature;
LASSO_EXPORT extern gboolean lasso_flag_sign_messages;
LASSO_EXPORT extern gboolean lasso_flag_thin_sessions;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DEBUG_H__ */
