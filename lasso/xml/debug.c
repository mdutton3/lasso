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

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <lasso/xml/debug.h>

#define normal "\033[m"
#define red    "\033[31m"
#define green  "\033[32m"
#define yellow "\033[33m"
#define blue   "\033[34m"

int  debug_line;
char debug_filename[512];
char debug_function[512];
static const char *errorcode[4] = {
  "DEBUG:",
  "INFO:", 
  "WARNING:",
  "ERROR:"
};

void
set_debug_info(int   line,
	       char *filename,
	       char *function)
{
  debug_line = line;
  strncpy(debug_filename, filename, 512);
  strncpy(debug_function, function, 512);
}

void
_debug(unsigned int level,
       const char *format, ...) 
{
  char debug_string[1024];
  char new_debug_string[2048];
  time_t ts;
  char date[20];
  char *color;

  va_list args;
  
  if ((level < 0) || (level > 3)) {
    printf("DEBUG LEVEL level=%d, must be 0<=x<=3 !!!\n");
    return;
  }

  va_start(args, format);
  vsnprintf(debug_string, sizeof(debug_string), format, args);
  va_end(args);

  time(&ts);
  strftime(date, 20, "%d-%m-%Y %H:%M:%S", localtime(&ts));

  switch (level) {
  case ERROR:
    color = red;
    break;
  case WARNING:
    color = blue;
    break;
  case DEBUG:
    color = yellow;
    break;
  case INFO:
    color = green;
    break;
  }

  sprintf(new_debug_string, 
	  "%s%s%s %s (%s/%s:%d)\t%s", 
	  color,
	  errorcode[level],
	  normal,
	  date,
	  debug_filename, debug_function,
	  debug_line, debug_string);

  printf("%s", new_debug_string);
  fflush(stdout);
}
