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
#include <com_entrouvert_lasso_LassoAuthnRequest.h>
#include <lasso/lasso.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_init
(JNIEnv * env, jobject this, jstring _providerID){
    LassoNode * request;
    char * providerID;

    providerID = (char*)(*env)->GetStringUTFChars(env, _providerID, NULL);

    request = lasso_authn_request_new(providerID);

    (*env)->ReleaseStringUTFChars(env, _providerID, providerID);

    storeCObject(env, this, request);
}

/* From LassoLibAuthnRequest */

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setAffiliationID
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_affiliationID((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setassertionConsumerServiceID
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_assertionConsumerServiceID((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setConsent
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_consent((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setForceAuthn
(JNIEnv * env, jobject this, jboolean _value){
    LassoAuthnRequest * request;

    request = getCObject(env, this);
    lasso_lib_authn_request_set_forceAuthn((LassoLibAuthnRequest*)request, _value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setPassive
(JNIEnv * env, jobject this, jboolean _value){
    LassoAuthnRequest * request;
    char * value;

    request = getCObject(env, this);
    lasso_lib_authn_request_set_isPassive((LassoLibAuthnRequest*)request, _value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setNameIdPolicy
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_nameIDPolicy((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setProtocolProfile
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_protocolProfile((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setproviderID
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_providerID((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}


JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoAuthnRequest_setRelayState
(JNIEnv * env, jobject this, jstring _value){
    LassoAuthnRequest * request;
    char * value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);

    request = getCObject(env, this);
    lasso_lib_authn_request_set_relayState((LassoLibAuthnRequest*)request, value);

    (*env)->ReleaseStringUTFChars(env, _value, value);
}


