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
#include <com_entrouvert_lasso_LassoAuthnResponse.h>
#include <lasso/lasso.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnResponse_init
(JNIEnv * env, jobject this, jstring _providerID, jobject _request){
    LassoNode * response;
    char * providerID;
    LassoNode * request;

    providerID = (char*)(*env)->GetStringUTFChars(env, _providerID, NULL);
    request = getCObject(env, _request);

    response = lasso_authn_response_new(providerID, request);

    (*env)->ReleaseStringUTFChars(env, _providerID, providerID);

    setCObject(env, this, response);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoAuthnResponse_getStatus
(JNIEnv * env, jobject this){
    LassoAuthnResponse * response;
    char* result;

    response = getCObject(env, this);
    result = lasso_authn_response_get_status(response);

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnResponse_setContent
(JNIEnv * env, jobject this, jstring _value){
    LassoLibAuthnResponse * response;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    response = getCObject(env, this);
    lasso_lib_authn_response_set_consent(response, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnResponse_setProviderID
(JNIEnv * env, jobject this, jstring _value){
    LassoLibAuthnResponse * response;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    response = getCObject(env, this);
    lasso_lib_authn_response_set_providerID(response, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnResponse_setRelayState
(JNIEnv * env, jobject this, jstring _value){
LassoLibAuthnResponse * response;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    response = getCObject(env, this);
    lasso_lib_authn_response_set_relayState(response, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

