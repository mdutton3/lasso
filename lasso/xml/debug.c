/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/debug.h>

int debug_line;
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
  char *color;

  va_list args;
  
  if ((level < 0) || (level > 2)) {
    printf("DEBUG LEVEL level=%d, must be 0<=x<=2 !!!\n");
    return;
  }
 
  va_start(args, format);
  vsprintf(debug_string, format, args);
  va_end(args);

  switch (level) {
  case ERROR:
    color = red;
    break;
  case WARNING:
    color = blue;
    break;
  case DEBUG:
  case INFO:
    color = green;
    break;
  }

  sprintf(new_debug_string, 
	  "%s%s%s (%s/%s:%d)\t%s", 
	  color,
	  errorcode[level],
	  black,
	  debug_filename, debug_function,
	  debug_line, debug_string);

  printf("%s", new_debug_string);
  fflush(stdout);
}
