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
#include <lasso/lasso.h>
#include <com_entrouvert_lasso_LassoProfile.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_getCIdentity
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * fieldName = "identity";
    char * fieldType = "Lcom/entrouvert/lasso/LassoIdentity;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoIdentity";
    LassoIdentity *identity;

    profile = getCObject(env, this);
    identity = lasso_profile_get_identity(profile);
    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, identity);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_getCRequest
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * fieldName = "request";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *request;

    profile = getCObject(env, this);
    request = profile->request;

    if (profile->request_type == lassoMessageTypeAuthnRequest) {
        javaObjectClassName = "com/entrouvert/lasso/LassoAuthnRequest";
    } else if (profile->request_type == lassoMessageTypeRequest) {
        javaObjectClassName = "com/entrouvert/lasso/LassoRequest";
    } else {
        /* FIXME: Throw error */
    }
    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, request);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_getCResponse
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * fieldName = "response";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *response;

    profile = getCObject(env, this);
    response = profile->response;

    if (profile->response_type == lassoMessageTypeAuthnResponse) {
        javaObjectClassName = "com/entrouvert/lasso/LassoAuthnResponse";
    } else if (profile->response_type == lassoMessageTypeResponse) {
        javaObjectClassName = "com/entrouvert/lasso/LassoResponse";
    } else {
        /* FIXME: Throw error */
    }
    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, response);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_getCServer
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * fieldName = "server";
    char * fieldType = "Lcom/entrouvert/lasso/LassoServer;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoServer";
    LassoServer *server;

    profile = getCObject(env, this);
    server = profile->server;
    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, server);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_getCSession
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * fieldName = "session";
    char * fieldType = "Lcom/entrouvert/lasso/LassoSession;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoSession";
    LassoSession *session;

    profile = getCObject(env, this);
    session = lasso_profile_get_session(profile);

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, session);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getMsgBody
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->msg_body;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getMsgRelayState
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->msg_relayState;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getMsgUrl
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->msg_url;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getNameIdentifier
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char *result;

    profile = getCObject(env, this);

    result = profile->nameIdentifier;
    if (result == NULL)
        return NULL;
    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getProviderID
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->remote_providerID;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_getRequestType
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    return profile->request_type;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_getResponseType
(JNIEnv *env, jobject this) {
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    return profile->response_type;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_setCIdentity
(JNIEnv *env, jobject this) {
    char *fieldName = "identity";
    char *fieldType = "Lcom/entrouvert/lasso/LassoIdentity;";
    jobject _identity;
    LassoIdentity *identity;
    LassoProfile *profile;

    profile = getCObject(env, this);
    _identity = getJavaObjectField(env, this, fieldName, fieldType);
    identity = getCObject(env, _identity);
    return lasso_profile_set_identity(profile, identity);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_setCSession
(JNIEnv *env, jobject this) {
    char *fieldName = "session";
    char *fieldType = "Lcom/entrouvert/lasso/LassoSession;";
    jobject _session;
    LassoSession *session;
    LassoProfile *profile;

    profile = getCObject(env, this);
    _session = getJavaObjectField(env, this, fieldName, fieldType);
    session = getCObject(env, _session);
    return lasso_profile_set_session(profile, session);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_setIdentityFromDump
(JNIEnv *env, jobject this, jstring _dump) {
    int result;
    LassoProfile *profile;
    char *dump;

    profile = getCObject(env, this);
    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    result = lasso_profile_set_identity_from_dump(profile, dump);
    (*env)->ReleaseStringUTFChars(env, _dump, dump);
    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_setSessionFromDump
(JNIEnv *env, jobject this, jstring _dump) {
    int result;
    LassoProfile *profile;
    char *dump;

    profile = getCObject(env, this);
    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    result = lasso_profile_set_session_from_dump(profile, dump);
    (*env)->ReleaseStringUTFChars(env, _dump, dump);
    return result;
}

