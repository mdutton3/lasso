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

#ifndef _HELPER_H_
#define _HELPER_H_

#include <jni.h>

/**
* If field in Java object don't represent C object, then create new Java
* object representation for this C object and set java field.
*/
void checkAndSetField(JNIEnv * env, jobject this, char * fieldName,
		      char * fieldType, char * javaObjectClassName, void * cObject);

/**
* Get C object from Java object
*/
void *getCObject(JNIEnv * env, jobject this);

/**
* Get value of attribute, attribute must be Java object
*/
jobject getJavaObjectField(JNIEnv * env, jobject this, const char * fieldName,
			   const char * fieldType);

/**
* Get pointer object stored in java field
* @param name name of field used to store pointer
* @return object pointer
*/
void *getObjectRef(JNIEnv * env, jobject this, const char * name);

/**
* Instantiate a new object. Default constructor used
*/
jobject instantiate(JNIEnv * env, const char * className);

/**
* Check if Java object store the C object passed in parameter
*/
int isSameObject(JNIEnv * env, jobject javaObject, void* cObject);

/**
* Store C object in Java object
*/
void setCObject(JNIEnv * env, jobject this, void * cobject);

/**
* Store new value for Java object attribute, attribute must be Java object
*/
void setJavaObjectField(JNIEnv * env, jobject this, const char * name, const char * fieldType,
			jobject value);

/**
* Store object pointer in java field
* @param name name of field used to store pointer
* @param objectRef pointer to store
*/
void setObjectRef(JNIEnv * env, jobject this, const char * name, void * objectRef);

#endif
