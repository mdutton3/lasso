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
#include <com_entrouvert_lasso_Lasso.h>
#include <lasso/lasso.h>

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_Lasso_init
(JNIEnv * env, jclass clazz){
    return lasso_init();
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_Lasso_shutdown
(JNIEnv * env, jclass clazz){
    return lasso_shutdown();
}

JNIEXPORT jint JNICALL Java_com_entrouvert_lasso_Lasso_getRequestTypeFromSoapMsg
(JNIEnv * env, jclass clazz, jstring _value){
    int result;
    char *value;

    value = (char*)(*env)->GetStringUTFChars(env, _value, NULL);
    result = lasso_profile_get_request_type_from_soap_msg(value);
    (*env)->ReleaseStringUTFChars(env, _value, value);
    return result;
}
