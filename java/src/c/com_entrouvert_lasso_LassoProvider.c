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
#include <com_entrouvert_lasso_LassoProvider.h>

JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoProvider_initMetadataField
(JNIEnv * env, jobject this){
    LassoProvider * provider;
    char * fieldName = "metadata";
    char * fieldType = "Lcom/entrouvert/lasso/LassoNode;";
    char * javaObjectClassName = "com/entrouvert/lasso/LassoNode";
    LassoNode *cObject;

    provider = getCObject(env, this);
    cObject = provider->metadata;

    checkAndSetField(env, this, fieldName, fieldType, javaObjectClassName, cObject);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProvider_getPublicKeyField
(JNIEnv * env, jobject this){
    LassoProvider * provider;
    char * result;

    provider = getCObject(env, this);

    result = provider->public_key;

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL Java_com_entrouvert_lasso_LassoProvider_getCertificateField
(JNIEnv * env, jobject this){
    LassoProvider * provider;
    char * result;

    provider = getCObject(env, this);

    result = provider->ca_certificate;

    return (*env)->NewStringUTF(env, result);
}

