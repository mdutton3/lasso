/*
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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
#include <com_entrouvert_lasso_LassoSession.h>
#include <lasso/lasso.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoSession_init
(JNIEnv * env, jobject this){
    LassoSession *session;

    session = lasso_session_new();

    setCObject(env, this, session);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoSession_initFromDump
(JNIEnv * env, jobject this, jstring _dump){
    LassoSession *session;
    char *dump;

    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    session = lasso_session_new_from_dump(dump);

    (*env)->ReleaseStringUTFChars(env, _dump, dump);

    setCObject(env, this, session);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoSession_dump
(JNIEnv * env, jobject this){
    LassoSession *session;
    char* result;

    session = (LassoSession*)getCObject(env, this);
    result = lasso_session_dump(session);

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoSession_getAuthenticationMethod
(JNIEnv * env, jobject this, jstring _remoteProviderId){
    char *remoteProviderId = NULL;
    char *result;
    LassoSession* session;

    if (_remoteProviderId)
        remoteProviderId = (char*)(*env)->GetStringUTFChars(env, _remoteProviderId, NULL);

    session = getCObject(env, this);
    result = lasso_session_get_authentication_method(session, remoteProviderId);

    if (_remoteProviderId)
        (*env)->ReleaseStringUTFChars(env, _remoteProviderId, remoteProviderId);

    return (*env)->NewStringUTF(env, result);
}

