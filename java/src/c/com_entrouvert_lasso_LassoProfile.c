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

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getMsgBody
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->msg_body;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getMsgRelayState
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->msg_relayState;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getMsgUrl
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->msg_url;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getNameIdentifier
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char *result;

    profile = getCObject(env, this);

    result = profile->nameIdentifier;
    if (result == NULL)
        return NULL;
    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfile_getProviderID
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    result = profile->remote_providerID;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_getRequestType
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    return profile->request_type;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_getResponseType
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * result;

    profile = getCObject(env, this);

    return profile->response_type;
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_initRequestField
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * fieldName = "request";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *cObject;

    profile = getCObject(env, this);
    cObject = profile->request;

    if (profile->request_type == lassoMessageTypeAuthnRequest) {
        javaObjectClassName = "com/entrouvert/lasso/LassoAuthnRequest";
    } else if(profile->request_type == lassoMessageTypeRequest) {
        javaObjectClassName = "com/entrouvert/lasso/LassoRequest";
    } else {
        /* FIXME: Throw error */
    }
    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_initResponseField
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * fieldName = "response";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *cObject;

    profile = getCObject(env, this);
    cObject = profile->response;

    if(profile->response_type == lassoMessageTypeAuthnResponse){
        javaObjectClassName = "com/entrouvert/lasso/LassoAuthnResponse";
    }else if(profile->response_type == lassoMessageTypeResponse){
        javaObjectClassName = "com/entrouvert/lasso/LassoResponse";
    }else{
        /* FIXME: Throw error */
    }

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_initServerField
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * fieldName = "server";
    char * fieldType = "Lcom/entrouvert/lasso/LassoServer;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoServer";
    LassoServer *cObject;

    profile = getCObject(env, this);
    cObject = profile->server;

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfile_initUserField
(JNIEnv * env, jobject this){
    LassoProfile * profile;
    char * fieldName = "user";
    char * fieldType = "Lcom/entrouvert/lasso/LassoUser;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoUser";
    LassoUser *cObject;

    profile = getCObject(env, this);
    cObject = profile->user;

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfile_setUserFromDump
(JNIEnv * env, jobject this, jstring _dump) {
    int result;
    LassoProfile *profile;
    char *dump;

    profile = getCObject(env, this);
    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    result = lasso_profile_set_user_from_dump(profile, dump);
    (*env)->ReleaseStringUTFChars(env, _dump, dump);
    return result;
}

