/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_DEBUG_H__
#define __LASSO_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <glib.h>

#define DEBUG   0 /* for debug - print only if flags LASSO_DEBUG is defined */
#define INFO    1 /* just print info */
#define WARNING 2 /* non fatal errors */
#define ERROR   3 /* criticial/fatal errors */

void set_debug_info(int line, char *filename, char *function);
void _debug(GLogLevelFlags level, const char *format, ...);

#if defined LASSO_DEBUG
#define debug(format, args...) set_debug_info(__LINE__, __FILE__, __FUNCTION__);  _debug(G_LOG_LEVEL_DEBUG, format, ##args);
#else
#define debug(format, ...);
#endif

#define message(level, format, args...) _debug(level, format, ##args);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DEBUG_H__ */
