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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TESTS_H__
#define __TESTS_H__

#include "../lasso/lasso_config.h"

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

#define check_equals(what,to) \
{	typeof(what) __tmp1, __tmp2; \
	__tmp1 = (what); \
	__tmp2 = (to); \
	fail_unless(__tmp1 == __tmp2, "%s:%i: " #what " is not equal to " #to "(%llu) but to %llu", __func__, __LINE__, (long long int)__tmp2, (long long int)__tmp1); \
}

#define check_not_equals(what,to) \
{	typeof(what) __tmp1, __tmp2; \
	__tmp1 = (what); \
	__tmp2 = (to); \
	fail_unless(__tmp1 != __tmp2, "%s:%i: " #what " is equal to " #to "(%llu)", __func__, __LINE__, (long long int)__tmp2); \
}

#define check_str_equals(what, to) \
{	typeof(what) __tmp; \
	__tmp = (what); \
	fail_unless(g_strcmp0(__tmp, to) == 0, "%s:%i: " #what " (%s) is not equal to %s", __func__, __LINE__, __tmp, to); \
}

#define check_str_not_equals(what, to) \
{	typeof(what) __tmp; \
	__tmp = (what); \
	fail_unless(g_strcmp0(__tmp, to) != 0, "%s:%i: " #what " is equal to %s", __func__, __LINE__, to); \
}

void mute_logger(G_GNUC_UNUSED const gchar *domain,
		G_GNUC_UNUSED GLogLevelFlags log_level, G_GNUC_UNUSED const gchar *message,
		G_GNUC_UNUSED gpointer user_data);

void fail_logger(const gchar *log_domain, GLogLevelFlags log_level,
		 const gchar *message, G_GNUC_UNUSED gpointer user_data);

#define block_lasso_logs g_log_set_default_handler(mute_logger, NULL);

#define unblock_lasso_logs g_log_set_default_handler(fail_logger, NULL);


#define CHECKING_LOG_HANDLER_SIZE 30

struct CheckingLogHandlerUserData {
		GLogLevelFlags log_levels[CHECKING_LOG_HANDLER_SIZE];
		const char *messages[CHECKING_LOG_HANDLER_SIZE];
		gboolean endswith[CHECKING_LOG_HANDLER_SIZE];
		GLogLevelFlags log_level_found;
		char *message_found;
};
G_GNUC_UNUSED static guint checking_log_handler = 0;
G_GNUC_UNUSED static guint checking_log_handler_flag = 0;
G_GNUC_UNUSED static struct CheckingLogHandlerUserData checking_logger_user_data;

static inline gboolean check_message(const char *a, const char *b, gboolean endswith) {
	if (endswith) {
		return strlen(a) >= strlen(b) &&
			strcmp(a+(strlen(a)-strlen(b)), b) == 0;
	} else {
		return strcmp(a, b) == 0;
	}
}

static inline void checking_logger(G_GNUC_UNUSED const gchar *domain,
		G_GNUC_UNUSED GLogLevelFlags log_level, G_GNUC_UNUSED const gchar *message,
		G_GNUC_UNUSED gpointer user_data) {
	struct CheckingLogHandlerUserData *ck_user_data = user_data;
	int i = 0;
	for (i = 0; i < CHECKING_LOG_HANDLER_SIZE; i++) {
		if (log_level == ck_user_data->log_levels[i] && check_message(message, ck_user_data->messages[i],
				ck_user_data->endswith[i])) {
			ck_user_data->log_level_found = log_level;
			ck_user_data->message_found = g_strdup(message);
			return;
		}
	}
	g_log_default_handler(domain, log_level, message, user_data);
	checking_log_handler_flag = 0;
}

static inline void add_check_log(GLogLevelFlags log_level, const char *message, gboolean endswith) {
	int i = 0;

	for (i = 0; i < CHECKING_LOG_HANDLER_SIZE-1; i++) {
		if (! checking_logger_user_data.messages[i]) {
			checking_logger_user_data.log_levels[i] = log_level;
			checking_logger_user_data.messages[i] = message;
			checking_logger_user_data.endswith[i] = endswith;
			return;
		}
	}
	g_assert_not_reached();
}

/* begin_check_do_log(level, message, endswith)/end_check_do_log() with check that the only
 * message emitted between the two macros is one equals to message at the level level,
 * or ending with message if endswith is True.
 */
static inline void begin_check_do_log(GLogLevelFlags level, const char *message, gboolean endswith) {
	memset(&checking_logger_user_data, 0, sizeof(struct CheckingLogHandlerUserData));
	add_check_log(level, message, endswith);
	checking_log_handler = g_log_set_handler(LASSO_LOG_DOMAIN, level, checking_logger, &checking_logger_user_data);
	checking_log_handler_flag = 1;
}

static inline void end_check_do_log() {
	g_log_remove_handler(LASSO_LOG_DOMAIN, checking_log_handler);
	checking_log_handler = 0;
	fail_unless(checking_log_handler_flag, "Logging failure: expected log level %d and message «%s», got %d and «%s»",
			checking_logger_user_data.log_levels[0],
			checking_logger_user_data.messages[0],
			checking_logger_user_data.log_level_found,
			checking_logger_user_data.message_found);
	if (checking_logger_user_data.message_found) {
		g_free(checking_logger_user_data.message_found);
	}
	checking_log_handler_flag = 0;
}

#endif /*__TESTS_H__ */
