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
#include <com_entrouvert_lasso_LassoServer.h>
#include <lasso/lasso.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoServer_init
(JNIEnv * env, jobject this, jstring _metadata,
                             jstring _publicKey,
                             jstring _privateKey,
                             jstring _certificate,
                             jint _signatureMethod){

    LassoServer *server;
    char *metadata;
    char *publicKey;
    char *privateKey;
    char *certificate;

    metadata = (char*)(*env)->GetStringUTFChars(env, _metadata, NULL);
    publicKey = (char*)(*env)->GetStringUTFChars(env, _publicKey, NULL);
    privateKey = (char*)(*env)->GetStringUTFChars(env, _privateKey, NULL);
    certificate = (char*)(*env)->GetStringUTFChars(env, _certificate, NULL);

    server = lasso_server_new(metadata, publicKey, privateKey,
                certificate, _signatureMethod);

    (*env)->ReleaseStringUTFChars(env, _metadata, metadata);
    (*env)->ReleaseStringUTFChars(env, _publicKey, publicKey);
    (*env)->ReleaseStringUTFChars(env, _privateKey, privateKey);
    (*env)->ReleaseStringUTFChars(env, _certificate, certificate);

    setCObject(env, this, server);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoServer_initFromDump
(JNIEnv * env, jobject this, jstring _dump){
    LassoServer *server;
    char *dump;

    dump = (char*)(*env)->GetStringUTFChars(env, _dump, NULL);
    server = lasso_server_new_from_dump(dump);

    (*env)->ReleaseStringUTFChars(env, _dump, dump);

    setCObject(env, this, server);
}

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoServer_addProvider
(JNIEnv * env, jobject this, jstring _metadata,
                             jstring _publicKey,
                             jstring _certificate){
    LassoServer *server;
    char *metadata;
    char *publicKey;
    char *certificate;

    metadata = (char*)(*env)->GetStringUTFChars(env, _metadata, NULL);
    publicKey = (char*)(*env)->GetStringUTFChars(env, _publicKey, NULL);
    certificate = (char*)(*env)->GetStringUTFChars(env, _certificate, NULL);

    server = (LassoServer*)getCObject(env, this);

    lasso_server_add_provider(server,
                metadata, publicKey, certificate);

    (*env)->ReleaseStringUTFChars(env, _metadata, metadata);
    (*env)->ReleaseStringUTFChars(env, _publicKey, publicKey);
    (*env)->ReleaseStringUTFChars(env, _certificate, certificate);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoServer_dump
(JNIEnv * env, jobject this){
    LassoServer *server;
    char* result;

    server = (LassoServer*)getCObject(env, this);
    result = lasso_server_dump(server);

    return (*env)->NewStringUTF(env, result);
}


JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoServer_destroy
(JNIEnv * env, jobject this){

    void* server = (LassoServer*)getCObject(env, this);

    lasso_server_destroy(server);
}

