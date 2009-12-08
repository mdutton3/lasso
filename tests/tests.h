/* $Id$ * * Lasso - A free implementation of the Liberty Alliance specifications.
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

#ifndef __TESTS_H__
#define __TESTS_H__

#define check_not_null(what) \
	fail_unless((what) != NULL, "%s:%i: " #what " returned NULL", __func__, __LINE__);

#define check_null(what) \
	fail_unless((what) == NULL, "%s:%i: "#what " returned NULL", __func__, __LINE__);

#define check_true(what) \
	fail_unless((what), "%s:%i: " #what " is not TRUE", __func__, __LINE__);

#define check_false(what) \
	fail_unless(! (what), "%s:%i: " #what " is not FALSE", __func__, __LINE__);


#define check_good_rc(what) \
{ 	int __rc = (what); \
	fail_unless(__rc == 0, "%s:%i: " #what " failed, rc = %s(%i)", __func__, __LINE__, lasso_strerror(__rc), __rc); \
}

#define check_bad_rc(what, how) \
{ 	int __rc = (what); \
	fail_unless(__rc == how, "%s:%i: " #what " is not %s(%i), rc = %s(%i)", __func__, __LINE__, lasso_strerror(how), how, lasso_strerror(__rc), __rc); \
}

#endif /*__TESTS_H__ */
