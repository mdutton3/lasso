/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include "errors.h"

const char*
lasso_strerror(int error_code)
{
  switch (error_code) {
  case LASSO_XML_ERROR_NODE_NOTFOUND:
    return "Unable to get '%s' child of '%s' element.\n";
  case LASSO_XML_ERROR_NODE_CONTENT_NOTFOUND:
    return "Unable to get content of '%s' element.\n";
  case LASSO_XML_ERROR_ATTR_NOTFOUND:
    return "Unable to get '%s' attribute of '%s' element.\n";
  case LASSO_XML_ERROR_ATTR_VALUE_NOTFOUND:
    return "Unable to get '%s' attribute value of '%s' element.\n";
  default:
    return "Undefined error code !!!\n";
  }
}
