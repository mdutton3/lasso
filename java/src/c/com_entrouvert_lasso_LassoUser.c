/* $Id$
 *
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
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

#include <helper.h>
#include <com_entrouvert_lasso_LassoUser.h>
#include <lasso/lasso.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoUser_init
(JNIEnv * env, jobject this){
    LassoUser *user;

    user = lasso_user_new();

    storeCObject(env, this, user);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoUser_initFromDump
(JNIEnv * env, jobject this, jstring _dump){
    LassoUser *user;
    char *dump;

    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    user = lasso_user_new_from_dump(dump);

    (*env)->ReleaseStringUTFChars(env, _dump, dump);

    storeCObject(env, this, user);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoUser_dump
(JNIEnv * env, jobject this){
    LassoUser *user;
    char* result;

    user = (LassoUser*)getCObject(env, this);
    result = lasso_user_dump(user);

    return (*env)->NewStringUTF(env, result);
}

