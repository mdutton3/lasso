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
#include <com_entrouvert_lasso_LassoProfileContext.h>

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getMsgBody
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * result;

    profileContext = getCObject(env, this);

    result = profileContext->msg_body;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getMsgRelayState
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * result;

    profileContext = getCObject(env, this);

    result = profileContext->msg_relayState;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getMsgUrl
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * result;

    profileContext = getCObject(env, this);

    result = profileContext->msg_url;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getNameIdentifier
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char *result;

    profileContext = getCObject(env, this);

    result = profileContext->nameIdentifier;
    if (result == NULL)
        return NULL;
    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getProviderID
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * result;

    profileContext = getCObject(env, this);

    result = profileContext->remote_providerID;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getRequestType
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * result;

    profileContext = getCObject(env, this);

    return profileContext->request_type;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoProfileContext_getResponseType
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * result;

    profileContext = getCObject(env, this);

    return profileContext->response_type;
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfileContext_initRequestField
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * fieldName = "request";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *cObject;

    profileContext = getCObject(env, this);
    cObject = profileContext->request;

    if (profileContext->request_type == lassoMessageTypeAuthnRequest) {
        javaObjectClassName = "com/entrouvert/lasso/LassoAuthnRequest";
    } else if(profileContext->request_type == lassoMessageTypeRequest) {
        javaObjectClassName = "com/entrouvert/lasso/LassoRequest";
    } else {
        /* FIXME: Throw error */
    }
    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfileContext_initResponseField
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * fieldName = "response";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *cObject;

    profileContext = getCObject(env, this);
    cObject = profileContext->response;

    if(profileContext->response_type == lassoMessageTypeAuthnResponse){
        javaObjectClassName = "com/entrouvert/lasso/LassoAuthnResponse";
    }else if(profileContext->response_type == lassoMessageTypeResponse){
        javaObjectClassName = "com/entrouvert/lasso/LassoResponse";
    }else{
        /* FIXME: Throw error */
    }

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfileContext_initServerField
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * fieldName = "server";
    char * fieldType = "Lcom/entrouvert/lasso/LassoServer;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoServer";
    LassoServer *cObject;

    profileContext = getCObject(env, this);
    cObject = profileContext->server;

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProfileContext_initUserField
(JNIEnv * env, jobject this){
    LassoProfileContext * profileContext;
    char * fieldName = "user";
    char * fieldType = "Lcom/entrouvert/lasso/LassoUser;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoUser";
    LassoUser *cObject;

    profileContext = getCObject(env, this);
    cObject = profileContext->user;

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

