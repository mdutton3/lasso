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

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <lasso/xml/debug.h>

/* #define normal "\033[m" */
/* #define red    "\033[31m" */
/* #define green  "\033[32m" */
/* #define yellow "\033[33m" */
/* #define blue   "\033[34m" */

int  debug_type;
int  debug_line;
char debug_filename[512];
char debug_function[512];

void
set_debug_info(int   line,
	       char *filename,
	       char *function,
	       int   type)
{
  debug_type = type;
  debug_line = line;
  debug_filename[511] = 0;
  debug_function[511] = 0;
  strncpy(debug_filename, filename, 511);
  strncpy(debug_function, function, 511);
}

void
_debug(GLogLevelFlags  level,
       const char     *format, ...) 
{
  char debug_string[1024];
  time_t ts;
  char date[20];
  va_list args;
  
  if (level == G_LOG_LEVEL_DEBUG && debug_type == 0) {
    g_warning("message() function should not be used with G_LOG_LEVEL_DEBUG level. Use debug() function rather.");
  }
  debug_type = 0;

  va_start(args, format);
  vsnprintf(debug_string, sizeof(debug_string), format, args);
  va_end(args);

  time(&ts);
  strftime(date, 20, "%d-%m-%Y %H:%M:%S", localtime(&ts));

  if (level == G_LOG_LEVEL_DEBUG || level == G_LOG_LEVEL_CRITICAL) {
    g_log("Lasso", level,
	  "%s (%s/%s:%d)\n======> %s",
	  date, debug_filename, debug_function, debug_line,
	  debug_string);
  }
  else {
    g_log("Lasso", level,
	  "%s\t%s",
	  date, debug_string);
  }
}
