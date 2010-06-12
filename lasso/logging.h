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

#ifndef __LASSO_LOGGING_H__
#define __LASSO_LOGGING_H__ 1

#include <glib.h>
#include "./errors.h"

#ifndef lasso_log
void lasso_log(GLogLevelFlags level, const char *filename, int line,
		const char *function, const char *format, ...);
#endif

int lasso_log_error_code(GLogLevelFlags level, int error, ...);

#ifndef __FUNCTION__
#  define __FUNCTION__  ""
#endif

#if defined(__GNUC__)
#  define message(level, format, args...) \
	lasso_log(level, __FILE__, __LINE__, __FUNCTION__, format, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define message(level, ...) \
	lasso_log(level, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#else
static inline void message(GLogLevelFlags level, const char *format, ...)
{
	va_list ap;
	char s[1024];
	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
	lasso_log(level, __FILE__, __LINE__, __FUNCTION__, s);
}
#endif


/* debug logging */
#if defined(LASSO_DEBUG)
#if defined(__GNUC__)
#define debug(format, args...) \
	message(G_LOG_LEVEL_DEBUG, format, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#define debug(...)     message(G_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
	static inline void debug(const char *format, ...)
	{
		va_list ap;
		char s[1024];
		va_start(ap, format);
		g_vsnprintf(s, 1024, format, ap);
		va_end(ap);
		message(G_LOG_LEVEL_DEBUG, "%s", s);
	}
#endif
#else
#if defined(__GNUC__)
#  define debug(format, args...) ;
#elif defined(HAVE_VARIADIC_MACROS)
#  define debug(...) ;
#else
	static inline void debug(const char *format, ...)
	{
		va_list ap;
		va_start(ap, format);
		va_end(ap);
	}
#endif
#endif

#if defined(__GNUC__)
#  define warning(format, args...) \
	message(G_LOG_LEVEL_DEBUG, format, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define warning(...)     message(G_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
static inline void warning(const char *format, ...)
{
	va_list ap;
	char s[1024];
	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
	message(G_LOG_LEVEL_WARNING, "%s", s);
}
#endif

#if defined(__GNUC__)
#  define critical(format, args...) \
	message(G_LOG_LEVEL_DEBUG, format, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define critical(...)     message(G_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
static inline void critical(const char *format, ...)
{
	va_list ap;
	char s[1024];
	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
	message(G_LOG_LEVEL_CRITICAL, "%s", s);
}
#endif

#define critical_error(rc) (critical("%s", lasso_strerror(rc)), rc)

#endif /* __LASSO_LOGGING_H_ */
