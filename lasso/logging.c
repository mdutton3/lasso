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

#include "logging.h"
#include "lasso_config.h"
#include <glib.h>
#include <time.h>

void
lasso_log(GLogLevelFlags level, const char *filename, int line,
		const char *function, const char *format, ...)
{
	char debug_string[1024];
	time_t ts;
	char date[20];
	va_list args;

	va_start(args, format);
	g_vsnprintf(debug_string, 1024, format, args);
	va_end(args);

	time(&ts);
	strftime(date, 20, "%Y-%m-%d %H:%M:%S", localtime(&ts));

	if (level == G_LOG_LEVEL_DEBUG || level == G_LOG_LEVEL_CRITICAL) {
		g_log(LASSO_LOG_DOMAIN, level, "%s (%s/%s:%d) %s",
				date, filename, function, line, debug_string);
	} else {
		g_log(LASSO_LOG_DOMAIN, level, "%s\t%s", date, debug_string);
	}
}

int
lasso_log_error_code(G_GNUC_UNUSED GLogLevelFlags level, int error, ...)
{
	const char *format;
	char message[1024];
	va_list args;

	format = lasso_strerror(error);

	va_start(args, error);
	g_vsnprintf(message, 1024, format, args);
	va_end(args);

	return error;
}
