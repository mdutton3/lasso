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
#include <com_entrouvert_lasso_LassoLogin.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoLogin_init
(JNIEnv * env, jobject this, jobject _server,
                             jobject _user){
    LassoLogin *login;
    LassoServer* server;
    LassoUser* user = NULL;

    server = (LassoServer*)getCObject(env, _server);
    if(_user != NULL){
        user = (LassoUser*)getCObject(env, _user);
    }

     login = LASSO_LOGIN(lasso_login_new(server, user));

    storeCObject(env, this, login);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoLogin_initFromDump
(JNIEnv * env, jobject this, jobject _server,
                             jobject _user,
                             jstring _dump){
    LassoLogin *login;
    LassoServer* server;
    char *dump;
    LassoUser* user = NULL;

    server = (LassoServer*)getCObject(env, _server);
    if(_user != NULL){
        user = (LassoUser*)getCObject(env, _user);
    }

    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    login = LASSO_LOGIN(lasso_login_new_from_dump(server, user, dump));
    (*env)->ReleaseStringUTFChars(env, _dump, dump);

    storeCObject(env, this, login);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_buildArtifactMsg
(JNIEnv * env, jobject this, jint _authenticationResult,
                             jstring _authenticationMethod,
                             jstring _reauthenticateOnOrAfter,
                             jint _method){
    int result;
    LassoLogin* login;
    char *authenticationMethod;
    char *reauthenticateOnOrAfter;

    authenticationMethod = (char*)(*env)->GetStringUTFChars(env, _authenticationMethod, NULL);
    reauthenticateOnOrAfter = (char*)(*env)->GetStringUTFChars(env, _reauthenticateOnOrAfter, NULL);

    login = getCObject(env, this);
    result = lasso_login_build_artifact_msg(login,
                       _authenticationResult,
                       authenticationMethod,
                       reauthenticateOnOrAfter,
                       _method);

    (*env)->ReleaseStringUTFChars(env, _authenticationMethod, authenticationMethod);
    (*env)->ReleaseStringUTFChars(env, _reauthenticateOnOrAfter, reauthenticateOnOrAfter);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_buildAuthnRequestMsg
(JNIEnv * env, jobject this){
    int result;
    LassoLogin* login;

    login = getCObject(env, this);
    result = lasso_login_build_authn_request_msg(login);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_buildAuthnResponseMsg
(JNIEnv * env, jobject this, jint _authenticationResult,
                             jstring _authenticationMethod,
                             jstring _reauthenticateOnOrAfter){
    int result;
    LassoLogin* login;
    char *authenticationMethod;
    char *reauthenticateOnOrAfter;

    authenticationMethod = (char*)(*env)->GetStringUTFChars(env, _authenticationMethod, NULL);
    reauthenticateOnOrAfter = (char*)(*env)->GetStringUTFChars(env, _reauthenticateOnOrAfter, NULL);

    login = getCObject(env, this);
    result = lasso_login_build_authn_response_msg(login,
                       _authenticationResult,
                       authenticationMethod,
                       reauthenticateOnOrAfter);

    (*env)->ReleaseStringUTFChars(env, _authenticationMethod, authenticationMethod);
    (*env)->ReleaseStringUTFChars(env, _reauthenticateOnOrAfter, reauthenticateOnOrAfter);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_buildRequestMsg
(JNIEnv * env, jobject this){
    int result;
    LassoLogin* login;

    login = getCObject(env, this);
    result = lasso_login_build_request_msg(login);

    return result;}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoLogin_dump
(JNIEnv * env, jobject this){
    char* result;
    LassoLogin* login;

    login = getCObject(env, this);
    result = lasso_login_dump(login);

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_initAuthnRequest
(JNIEnv * env, jobject this, jstring _providerID){
    int result;
    LassoLogin* login;
    char *providerID;

    providerID = (char*)(*env)->GetStringUTFChars(env, _providerID, NULL);

    login = getCObject(env, this);
    result = lasso_login_init_authn_request(login,
                       providerID);

    (*env)->ReleaseStringUTFChars(env, _providerID, providerID);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_initFromAuthnRequestMsg
(JNIEnv * env, jobject this, jstring _authnRequestMsg,
                             jint _authnRequestMethod){
    int result;
    LassoLogin* login;
    char *authnRequestMsg;

    authnRequestMsg = (char*)(*env)->GetStringUTFChars(env, _authnRequestMsg, NULL);

    login = getCObject(env, this);
    result = lasso_login_init_from_authn_request_msg(login,
                       authnRequestMsg,
                       _authnRequestMethod);

    (*env)->ReleaseStringUTFChars(env, _authnRequestMsg, authnRequestMsg);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_initRequest
(JNIEnv * env, jobject this, jstring _responseMsg,
                             jint _responseMethod){
    int result;
    LassoLogin* login;
    char *responseMsg;

    responseMsg = (char*)(*env)->GetStringUTFChars(env, _responseMsg, NULL);

    login = getCObject(env, this);
    result = lasso_login_init_request(login,
                       responseMsg,
                       _responseMethod);

    (*env)->ReleaseStringUTFChars(env, _responseMsg, responseMsg);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_mustAuthenticate
(JNIEnv * env, jobject this){
    int result;
    LassoLogin* login;

    login = getCObject(env, this);
    result = lasso_login_must_authenticate(login);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_processAuthnResponseMsg
(JNIEnv * env, jobject this, jstring _authnResponseMsg){
    int result;
    LassoLogin* login;
    char *authnResponseMsg;

    authnResponseMsg = (char*)(*env)->GetStringUTFChars(env, _authnResponseMsg, NULL);

    login = getCObject(env, this);
    result = lasso_login_process_authn_response_msg(login,
                       authnResponseMsg);

    (*env)->ReleaseStringUTFChars(env, _authnResponseMsg, authnResponseMsg);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_processRequestMsg
(JNIEnv * env, jobject this, jstring _requestMsg){
    int result;
    LassoLogin* login;
    char *requestMsg;

    requestMsg = (char*)(*env)->GetStringUTFChars(env, _requestMsg, NULL);

    login = getCObject(env, this);
    result = lasso_login_process_request_msg(login,
                       requestMsg);

    (*env)->ReleaseStringUTFChars(env, _requestMsg, requestMsg);

    return result;
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_LassoLogin_processResponseMsg
(JNIEnv * env, jobject this, jstring _responseMsg){
    int result;
    LassoLogin* login;
    char *responseMsg;

    responseMsg = (char*)(*env)->GetStringUTFChars(env, _responseMsg, NULL);

    login = getCObject(env, this);
    result = lasso_login_process_response_msg(login,
                       responseMsg);

    (*env)->ReleaseStringUTFChars(env, _responseMsg, responseMsg);

    return result;
}

