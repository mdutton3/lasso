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

void checkAndSetField(JNIEnv *env, jobject this, char *fieldName,
		      char *fieldType, char *javaObjectClassName, void *cObject) {
    jobject javaObject;

    /* check if changes are made */
    javaObject = getJavaObjectField(env, this, fieldName, fieldType);
    if(isSameObject(env, javaObject, cObject)){
        /* no change made, do nothing */
        return;
    }

    javaObject = instantiate(env, javaObjectClassName);
    if(javaObject == NULL){
        return; /* exception thrown */
    }

    /* associate C object with JavaObject */
    setCObject(env, javaObject, cObject);
    setJavaObjectField(env, this, fieldName, fieldType, javaObject);
}

void * getCObject(JNIEnv * env, jobject this) {
    return getObjectRef(env, this, "c_lasso_object");
}

jobject getJavaObjectField(JNIEnv * env, jobject this, const char * fieldName,
			   const char * fieldType) {
    jclass clazz;
    jfieldID fid;
    jobject result;

    clazz = (*env)->GetObjectClass(env, this);
    fid = (*env)->GetFieldID(env, clazz, fieldName, fieldType);

    result = (*env)->GetObjectField(env, this, fid);
    return result;
}

void * getObjectRef(JNIEnv * env, jobject this, const char * name) {
    jclass clazz;
    jfieldID fid;
    jlong result;

    clazz = (*env)->GetObjectClass(env, this);
    fid = (*env)->GetFieldID(env, clazz, name, "J");

    result = (*env)->GetLongField(env, this, fid);
    return (void*)(long)result;
}

jobject instantiate(JNIEnv * env, const char * className){
    jclass clazz;
    jmethodID constructor;
    jobject result;

    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return NULL; /* exception thrown */
    }
    constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");
    if (constructor == NULL) {
        return NULL; /* exception thrown */
    }

    result = (*env)->NewObject(env, clazz, constructor);
    (*env)->DeleteLocalRef(env, clazz);

    return result;
}

int isSameObject(JNIEnv * env, jobject javaObject, void* cObject){
    return javaObject != NULL && cObject == getCObject(env, javaObject);
}

void setCObject(JNIEnv * env, jobject this, void * cobject) {
    setObjectRef(env, this, "c_lasso_object", cobject);
}

void setJavaObjectField(JNIEnv * env, jobject this, const char * fieldName, const char * fieldType, jobject value){
    jclass clazz;
    jfieldID fid;

    clazz = (*env)->GetObjectClass(env, this);
    fid = (*env)->GetFieldID(env, clazz, fieldName, fieldType);

    (*env)->SetObjectField(env, this, fid, value);
}

void setObjectRef(JNIEnv * env, jobject this, const char * name, void * objectRef) {
    jclass clazz;
    jfieldID fid;
    jlong ref;

    clazz = (*env)->GetObjectClass(env, this);
    fid = (*env)->GetFieldID(env, clazz, name, "J");

    ref = (jlong)(long)objectRef;
    (*env)->SetLongField(env, this, fid, ref);
}
