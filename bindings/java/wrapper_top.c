#include <glib.h>
#include <glib-object.h>
#include <lasso/lasso.h>
#include <config.h>
#include <jni.h>
#include "com_entrouvert_lasso_LassoJNI.h"
#include <string.h>
#include "../ghashtable.h"
#include "../../lasso/utils.h"
#include "../utils.c"
#include "../../lasso/backward_comp.h"

#define LASSO_ROOT "com/entrouvert/lasso/"
#define check_exception (*env)->ExceptionCheck(env)
#define g_return_val_if_exception(value) if ((*env)->ExceptionCheck(env)) return (value);
#define g_return_if_exception() if ((*env)->ExceptionCheck(env)) return;
#define convert_jlong_to_gobject(value) ((GObject*)(ptrdiff_t)value)
#define g_error_if_fail(value) { if (!(value)) { g_on_error_query("LassoJNI"); } }
#define PTR_TO_JLONG(x) (jlong)((ptrdiff_t)x)

static GQuark lasso_wrapper_key = 0;
typedef int (*Converter)(JNIEnv *env, void *from, jobject *to);
typedef int *(*OutConverter)(JNIEnv *env, jobject from, gpointer *to);

/* Static declarations */
G_GNUC_UNUSED static int gpointer_equal(const gpointer p1, const gpointer p2);
G_GNUC_UNUSED static int new_object_with_gobject(JNIEnv *env, GObject *obj, const char *clsName, jobject *jobj);
G_GNUC_UNUSED static int jstring_to_local_string(JNIEnv *env, jstring jstr, const char **str);
G_GNUC_UNUSED static void release_local_string(JNIEnv *env, jstring str, const char *utf_str);
G_GNUC_UNUSED static int get_jlong_field(JNIEnv *env, jobject obj, const char *field, jlong *dest);
G_GNUC_UNUSED static jclass get_jclass_by_name(JNIEnv *env, const char *name);
G_GNUC_UNUSED static int get_array_element(JNIEnv *env, jobjectArray arr, jsize i, jobject *dest);
G_GNUC_UNUSED static int set_array_element(JNIEnv *env, jobjectArray arr, jsize i, jobject value);
G_GNUC_UNUSED static int get_array_size(JNIEnv *env, jobjectArray arr, jsize *dest);
G_GNUC_UNUSED static int create_object_array(JNIEnv *env, const char *clsName, jsize size, jobjectArray *jarr);
G_GNUC_UNUSED static jobject get_shadow_object(JNIEnv *env, GObject *obj);
G_GNUC_UNUSED static void set_shadow_object(JNIEnv *env, GObject *obj, jobject shadow_object);
G_GNUC_UNUSED static void exception(JNIEnv *env, const char *message);
G_GNUC_UNUSED static int string_to_jstring(JNIEnv *env, const char* str, jstring *jstr);
G_GNUC_UNUSED static int string_to_jstring_and_free(JNIEnv *env, char* str, jstring *jstr);
G_GNUC_UNUSED static int jstring_to_string(JNIEnv *env, jstring jstr, char **str);
G_GNUC_UNUSED static int xml_node_to_jstring(JNIEnv *env, xmlNode *xmlnode, jstring *jstr);
G_GNUC_UNUSED static int jstring_to_xml_node(JNIEnv *env, jstring jstr, xmlNode **xmlnode);
G_GNUC_UNUSED static int gobject_to_jobject_aux(JNIEnv *env, GObject *obj, gboolean doRef, jobject *job);
G_GNUC_UNUSED static int gobject_to_jobject(JNIEnv *env, GObject *obj, jobject *jobj);
G_GNUC_UNUSED static int gobject_to_jobject_and_ref(JNIEnv *env, GObject *obj, jobject *jobj);

G_GNUC_UNUSED static int jobject_to_gobject(JNIEnv *env, jobject obj, GObject **gobj);
G_GNUC_UNUSED static int jobject_to_gobject_noref(JNIEnv *env, jobject obj, GObject **gobj);
G_GNUC_UNUSED static void free_glist(GList **list, GFunc free_function);
G_GNUC_UNUSED static int get_list(JNIEnv *env, const char *clsName, const GList *list, Converter convert, jobjectArray *jarr);
G_GNUC_UNUSED static int set_list(JNIEnv *env, GList **list, jobjectArray jarr, GFunc free_function, OutConverter convert);
G_GNUC_UNUSED static int remove_from_list(JNIEnv *env,GList **list,jobject obj,GFunc free_function,GCompareFunc compare,OutConverter convert);
G_GNUC_UNUSED static int add_to_list(JNIEnv* env, GList** list, jobject obj, OutConverter convert);
G_GNUC_UNUSED static int get_hash(JNIEnv *env, char *clsName, GHashTable *hashtable, Converter convert, jobjectArray *jarr);
G_GNUC_UNUSED static int set_hash_of_objects(JNIEnv *env, GHashTable *hashtable, jobjectArray jarr);
G_GNUC_UNUSED static int set_hash_of_strings(JNIEnv *env, GHashTable *hashtable, jobjectArray jarr);
G_GNUC_UNUSED static int remove_from_hash(JNIEnv *env, GHashTable *hashtable, jstring jkey);
G_GNUC_UNUSED static int add_to_hash(JNIEnv *env, GHashTable *hashtable, jstring jkey, jobject jvalue, OutConverter convert, GFunc free_function);
G_GNUC_UNUSED static int get_hash_by_name(JNIEnv *env, GHashTable *hashtable, jstring jkey, Converter convert, jobject *jvalue);
#define get_list_of_strings(env,list,jarr) get_list(env,"java/lang/String",list,(Converter)string_to_jstring,jarr)
#define get_list_of_xml_nodes(env,list,jarr) get_list(env,"java/lang/String",list,(Converter)xml_node_to_jstring,jarr)
#define get_list_of_objects(env,list,jarr) get_list(env,"java/lang/Object",list,(Converter)gobject_to_jobject_and_ref,jarr)
#define set_list_of_strings(env,list,jarr) set_list(env,list,jarr,(GFunc)g_free,(OutConverter)jstring_to_string)
#define set_list_of_xml_nodes(env,list,jarr) set_list(env,list,jarr,(GFunc)xmlFreeNode,(OutConverter)jstring_to_xml_node)
#define set_list_of_objects(env,list,jarr) set_list(env,list,jarr,(GFunc)g_object_unref,(OutConverter)jobject_to_gobject)
// remove_from_list_of_strings is now implemented directly
//#define remove_from_list_of_strings(env,list,obj) remove_from_list(env,list,obj,(GFunc)g_free,(GCompareFunc)strcmp,(OutConverter)jstring_to_local_string)
//#define remove_from_list_of_xml_nodes(env,list,obj) remove_from_list(env,list,obj,(GFunc)xmlFreeNode,(GCompareFunc)strcmp,(OutConverter)jstring_to_xml_node)
#define remove_from_list_of_objects(env,list,obj) remove_from_list(env,list,obj,(GFunc)g_object_unref,(GCompareFunc)gpointer_equal,(OutConverter)jobject_to_gobject_noref)
#define add_to_list_of_strings(env,list,obj) add_to_list(env,list,obj,(OutConverter)jstring_to_string)
#define add_to_list_of_xml_nodes(env,list,obj) add_to_list(env,list,obj,(OutConverter)jstring_to_xml_node)
// Use jobject_to_gobject_for_list because ref count must be augmented by one when inserted inside a list
#define add_to_list_of_objects(env,list,obj) add_to_list(env,list,obj,(OutConverter)jobject_to_gobject)
#define get_hash_of_strings(env,hash,jarr) get_hash(env,"java/lang/String",hash,(Converter)string_to_jstring, jarr)
#define get_hash_of_objects(env,hash,jarr) get_hash(env,"java/lang/Object",hash,(Converter)gobject_to_jobject_and_ref, jarr)
//#define remove_from_hash_of_strings(env,hash,key) remove_from_hash(env,hash,key)
//#define remove_from_hash_of_objects(env,hash,key) remove_from_hash(env,hash,key)
#define add_to_hash_of_strings(env,hash,key,obj) add_to_hash(env,hash,key,obj,(OutConverter)jstring_to_string,(GFunc)g_free)
#define add_to_hash_of_objects(env,hash,key,obj) add_to_hash(env,hash,key,obj,(OutConverter)jobject_to_gobject,(GFunc)g_object_unref)
//#define get_hash_of_strings_by_name(end,hash,key) get_hash_by_name(end,hash,key,(Converter)string_to_jstring)
//#define get_hash_of_objects_by_name(end,hash,key) get_hash_by_name(end,hash,key,(Converter)gobject_to_jobject_and_ref)
G_GNUC_UNUSED static void throw_by_name(JNIEnv *env, const char *name, const char *msg);


static int
gpointer_equal(const gpointer p1, const gpointer p2) {
    return p1 != p2;
}

static int
new_object_with_gobject(JNIEnv *env, GObject *obj, const char *clsName, jobject *jobj) {
    jclass cls;
    jmethodID mid;

    g_error_if_fail(env && clsName && obj && G_IS_OBJECT(obj));

    lasso_return_val_if_fail((cls = (*env)->FindClass(env, clsName)), 0);
    lasso_return_val_if_fail((mid = (*env)->GetMethodID(env, cls, "<init>", "(J)V")), 0);
    lasso_return_val_if_fail((*jobj = (*env)->NewObject(env, cls, mid, PTR_TO_JLONG(obj))), 0);
    return 1;
}

/** Convert a java string to a jstring */
static int
jstring_to_local_string(JNIEnv *env, jstring jstr, const char **str)
{
    g_error_if_fail(env);

    if (jstr) {
        *str = (*env)->GetStringUTFChars(env, jstr, NULL);
        lasso_return_val_if_fail(*str, 0);
    } else {
        *str = NULL;
    }
    return 1;
}

/** Release a local string. IT'S MANDATORY TO CALL THIS !!! */
static void
release_local_string(JNIEnv *env, jstring str, const char *utf_str) {
    g_error_if_fail(env);

    if (utf_str && str) {
        (*env)->ReleaseStringUTFChars(env, str, utf_str);
    }
}

static int
get_jlong_field(JNIEnv *env, jobject obj, const char *field, jlong *dest)
{
    jclass cls;
    jfieldID fid;

    cls = (*env)->GetObjectClass(env, obj);
    lasso_return_val_if_fail(cls, 0);
    fid = (*env)->GetFieldID(env, cls, field, "J");
    lasso_return_val_if_fail(fid, 0);
    *dest = (*env)->GetLongField(env, obj, fid);
    g_return_val_if_exception(0);

    return 1;
}

static jclass
get_jclass_by_name(JNIEnv *env, const char *name) {
    return (*env)->FindClass(env,name);
}

static int
get_array_element(JNIEnv *env, jobjectArray arr, jsize i, jobject *dest) {
    *dest = (*env)->GetObjectArrayElement(env, arr, i);
    lasso_return_val_if_fail(! (*env)->ExceptionCheck(env), 0);
    return 1;
}

static int
set_array_element(JNIEnv *env, jobjectArray arr, jsize i, jobject value) {
        (*env)->SetObjectArrayElement(env, arr, i, value);
        g_return_val_if_exception(0);
        return 1;
}
static int
get_array_size(JNIEnv *env, jobjectArray jarr, jsize *dest) {
    *dest = (*env)->GetArrayLength(env, jarr);
    g_return_val_if_exception(0);
    return 1;
}
static int
create_object_array(JNIEnv *env, const char *clsName, jsize size, jobjectArray *jarr) {
    jclass cls;

    g_error_if_fail(env && clsName && jarr);

    cls = get_jclass_by_name(env, clsName);
    lasso_return_val_if_fail(cls, 0);
    *jarr = (*env)->NewObjectArray(env, size, get_jclass_by_name(env, clsName), NULL);
    lasso_return_val_if_fail(*jarr, 0);
    return 1;
}
static int nullWeakRef(JNIEnv *env, jweak weakRef) {
    return weakRef && (*env)->IsSameObject(env, weakRef, NULL);
}
/** Return the shadow object associated with the gobject.
 *  If the weak global reference is dead, frees it.
 *  If not shadow object is present, return NULL. */
static jobject
get_shadow_object(JNIEnv *env, GObject *obj) {
    jweak weakRef;

    g_error_if_fail (obj && env);
    weakRef = (jweak)g_object_get_qdata(obj, lasso_wrapper_key);
    if (weakRef == NULL) {
        return NULL;
    } else if (nullWeakRef(env, weakRef)) {
        /** Remove null weak ref. */
        (*env)->DeleteWeakGlobalRef(env, weakRef);
        g_object_set_qdata(obj, lasso_wrapper_key, NULL);
        return NULL;
    } else {
        return (*env)->NewLocalRef(env, weakRef);
    }
}
/** Sets the java shadow object associated with the GObject obj.
 * If a shadow object is already present, frees its weak global reference.
 * Replacing a non NULL weak global reference by another one should not happend.
 * It means that two java shadow object for the same GObject exist at the same time
 */
static void
set_shadow_object(JNIEnv *env, GObject *obj, jobject shadow_object) {
    jweak weakRef;
    jweak old_weakRef;

    g_error_if_fail(obj && env);

    old_weakRef = (jweak)g_object_get_qdata(obj, lasso_wrapper_key);
    if (old_weakRef) {
        if (shadow_object != NULL && ! (*env)->IsSameObject(env, old_weakRef, NULL)) {
            g_warning("remplacement d'un shadow object non nulle par un shadow object non nulle %p %p", shadow_object, old_weakRef);
        }
        (*env)->DeleteWeakGlobalRef(env, old_weakRef);
    }
    g_object_set_qdata(obj, lasso_wrapper_key, NULL);
    if (shadow_object) {
        weakRef = (*env)->NewWeakGlobalRef(env, shadow_object);
        g_object_set_qdata(obj, lasso_wrapper_key, weakRef);
    }
}
/** Throw a new RuntimeException containing this message. */
static void
exception(JNIEnv *env, const char *message) {
    jclass cls = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (cls != NULL) {
        throw_by_name(env, "java/lang/RuntimeException", message);
    }
    (*env)->DeleteLocalRef(env, cls);
}

/* Conversion fonctions */
/** Convert a C string to java string. NULL is a valid C string giving a null
 * java object. */
static int
string_to_jstring(JNIEnv *env, const char* str, jstring *jstr) {
    if (str) {
        *jstr = (*env)->NewStringUTF(env, str);
        lasso_return_val_if_fail(jstr, 0);
    } else {
        *jstr = NULL;
    }
    return 1;
}

/** Convert a string to a java string then free it. Don't frees it
 * if conversion failed. */
static int
string_to_jstring_and_free(JNIEnv *env, char* str, jstring *jstr) {
    lasso_return_val_if_fail(string_to_jstring(env, str, jstr), 0);
    if (str)
        g_free(str);
    return 1;
}

/** Convert a jstring to a C string and copy it. Returned string is owner by the caller.*/
static int
jstring_to_string(JNIEnv *env, jstring jstr, char **str) {
    const char *local_str = NULL;

    lasso_return_val_if_fail(jstring_to_local_string(env, jstr, &local_str), 0);
    if (local_str) {
        lasso_assign_string(*str, local_str);
        release_local_string(env, jstr, local_str);
        if (!str) {
            /* Maybe launch a OutOfMemoryException. */
            exception(env, "could not alloc a copy of a jstring");
            return 0;
        }
    } else {
        *str = NULL;
    }
    return 1;
}


/* xmlNode handling */
static xmlBuffer*
xmlnode_to_xmlbuffer(xmlNode *node)
{
	xmlOutputBufferPtr output_buffer;
	xmlBuffer *buffer;

	if (! node)
		return NULL;

	buffer = xmlBufferCreate();
	output_buffer = xmlOutputBufferCreateBuffer(buffer, NULL);
	xmlNodeDumpOutput(output_buffer, NULL, node, 0, 0, NULL);
	xmlOutputBufferClose(output_buffer);
	xmlBufferAdd(buffer, BAD_CAST "", 1);

	return buffer;
}

static int
xml_node_to_jstring(JNIEnv *env, xmlNode *xmlnode, jstring *jstr) {
    xmlBuffer *buffer;

    g_error_if_fail(env);
    if (! xmlnode) {
        *jstr = NULL;
        return 1;
    }
    buffer = xmlnode_to_xmlbuffer(xmlnode);
    if (! buffer) {
        exception(env, "could not alloc an xml output buffer");
        return 0;
    }
    return string_to_jstring(env, (char*)xmlBufferContent(buffer), jstr);
}

/** Convert a java string to an xml node. Return 0 if it failed with an exception
 * throwed. */
static int
jstring_to_xml_node(JNIEnv *env, jstring jstr, xmlNode **xmlnode) {
    xmlDoc *doc = NULL;
    xmlNode *node = NULL;
    const char *local_str = NULL;
    int ret = 1;

    g_error_if_fail(env && xmlnode);
    lasso_return_val_if_fail(jstring_to_local_string(env, jstr, &local_str), 0);

    if (local_str) {
        node = lasso_string_fragment_to_xmlnode(local_str, 0);
    }
    lasso_assign_new_xml_node(*xmlnode, node)
    lasso_release_doc(doc);
    if (jstr && local_str)
        release_local_string(env, jstr, local_str);
    return ret;
}

/* lasso objects handling impl */
static void
create_class_name(char *dest, const char *typename) {
        char *ret = NULL;

        ret = strstr(typename, "Lasso");
        if (ret) {
            typename = ret+5;
        }
        strncpy(dest+sizeof(LASSO_ROOT)-1, typename,50);
        dest[sizeof(LASSO_ROOT)+49] = 0;
}
/** Convert the GObject obj to a java object encapsulating it.
 * If obj is NULL, return NULL.
 * Throws if obj is not a GObject or if anyhting fail. */
static int
gobject_to_jobject_aux(JNIEnv *env, GObject *obj, gboolean doRef, jobject *jobj) {
    jobject self = NULL;
    int ret = 1;

    if (obj == NULL) {
        goto out;
    }

    if (! G_IS_OBJECT(obj)) {
        exception(env, "tried to convert something that is not a GObject to a Java object");
        ret = 0;
        goto out;
    }

    /* Try to get an already created java object. */
    self = get_shadow_object(env, obj);
    if (self) {
        goto out;
    } else {
        /* Create the shadow object */
        char clsName[sizeof(LASSO_ROOT)+50] = LASSO_ROOT;
        const char *typename = NULL;

        typename = G_OBJECT_TYPE_NAME(obj);
        create_class_name(clsName, typename);
        if (! new_object_with_gobject(env, obj, clsName, &self)) {
            ret = 0;
            goto out;
        }
        set_shadow_object(env, obj, self);
        /** If all goes well increment reference count eventually. */
        if (doRef) {
            g_object_ref(obj);
        }
    }
out:
    *jobj = self;
    return ret;
}
/** Get or create a new java object encapsulating this lasso GObject, do not increase ref count if created. */
static int
gobject_to_jobject(JNIEnv *env, GObject *obj, jobject *jobj) {
    return gobject_to_jobject_aux(env, obj, FALSE, jobj);
}
/** Get or create a new java object encapsulating this lasso GObject, increase ref count if created. */
static int
gobject_to_jobject_and_ref(JNIEnv *env, GObject *obj, jobject *jobj) {
    return gobject_to_jobject_aux(env, obj, TRUE, jobj);
}

/** Get the gobject encapsulated by the java object obj. If cptr is
 * null return NULL.
 * It throws and return 0 if anything fail unexpectedly. */
static int
jobject_to_gobject(JNIEnv *env, jobject obj, GObject **gobj) {
    jlong value = 0;
    GObject *gobject = NULL;

    g_error_if_fail(env);

    if (! obj) {
        *gobj = NULL;
        return 1;
    }
    lasso_return_val_if_fail(get_jlong_field(env, obj, "cptr", &value), 0);
    gobject = convert_jlong_to_gobject(value);
    if (gobject && ! G_IS_OBJECT(gobject)) {
#define s "jobject->cptr is not a pointer on a gobject: XXXXXXXXXXXXXXXXXXXXXXX"
        char str[] = s;
        snprintf(str, sizeof(s)-1, "jobject->cptr is not a pointer on a gobject = %p", gobject);
        exception(env, str);
#undef s
        return 0;
    } else {
        lasso_assign_gobject(*gobj, gobject);
        return 1;
    }
}

/** Get the gobject encapsulated by the java object obj and increase its ref count. The only
 * use for this function is composed with set_list_of_objects or set_hash_of_object. */
static int
jobject_to_gobject_noref(JNIEnv *env, jobject obj, GObject **gobj) {
    lasso_return_val_if_fail(jobject_to_gobject(env, obj, gobj), 0);
    if (*gobj) {
        g_object_unref(*gobj);
    }
    return 1;
}

/* List handling */
static void
free_glist(GList **list, GFunc free_function) {
    lasso_return_if_fail(list);
    if (*list) {
        if (free_function) {
            g_list_foreach(*list, free_function, NULL);
        }
        g_list_free(*list);
    }
    *list = NULL;
}

/** Get an object array from a GList*, convert C object to java object using
 * the convert function.
 *
 * Can throw. If list is null or empty, return NULL.
 */
static int
get_list(JNIEnv *env, const char *clsName, const GList *list, Converter convert, jobjectArray *jarr) {
    jsize l,i;
    jclass cls;

    g_error_if_fail (env && clsName && convert);
    l = g_list_length((GList*)list);
    if (!l) {
        *jarr = NULL;
        goto out;
    }
    cls = get_jclass_by_name(env, clsName);
    lasso_return_val_if_fail(cls, 0);

    lasso_return_val_if_fail(create_object_array(env, clsName, l, jarr), 0);
    for (i=0;i<l;i++) {
        jobject item;

        lasso_return_val_if_fail(convert(env, list->data, &item), 0);
        lasso_return_val_if_fail(set_array_element(env, *jarr, i, item), 0);
        list = g_list_next(list);
    }
out:
    return 1;
}

/** Sets a GList* field using a java array of object. Use free_function if an old list exist.
 * Use convert to convert the java objects to C values. */
static int
set_list(JNIEnv *env, GList **list, jobjectArray jarr, GFunc free_function, OutConverter convert) {
    jobject element = NULL;
    jsize size = 0;
    jsize i = 0;
    GList *new = NULL;

    g_error_if_fail (list && free_function && convert && env);
    if (jarr) {
        if (! get_array_size(env, jarr, &size))
            goto error;
        for (i=0; i < size; i++) {
            gpointer result = NULL;

            if (! get_array_element(env, jarr, i, &element)
                || ! convert(env, element, &result)) {
                goto error;
            }
            new =  g_list_append(new, result);
        }
    }

    free_glist(list, free_function);
    *list = new;
    return 1;

error:
    free_glist(&new, free_function);
    return 0;
}
/** Remove a value obtained via the convert function on obj from *list.
 * It is searched inside *list using the compare function.
 * If pointer is found, it is freed using the free_function.
 * Return 0 if an exception was throwed.
 **/
static int
remove_from_list(JNIEnv *env, GList **list, jobject obj, GFunc free_function, GCompareFunc compare, OutConverter convert) {
    gpointer data = NULL;
    GList *found = NULL;

    g_error_if_fail(env && list && compare && convert && free_function);
    lasso_return_val_if_fail(obj, 1);
    lasso_return_val_if_fail(convert(env, obj, &data), 0);
    found = g_list_find_custom(*list, data, compare);
    if (found) {
        free_function(found->data, NULL);
        *list = g_list_delete_link(*list, found);
    }
    return 1;
}
static int
remove_from_list_of_strings(JNIEnv *env, GList **list, jstring jstr) {
    const char *local_string = NULL;
    GList *found = NULL;

    g_error_if_fail(env && list);
    lasso_return_val_if_fail(jstr, 1);
    lasso_return_val_if_fail(jstring_to_local_string(env, jstr, &local_string), 0);
    found = g_list_find_custom(*list, local_string, (GCompareFunc)g_strcmp0);
    if (found) {
        g_free(found->data);
        *list = g_list_delete_link(*list, found);
    }
    release_local_string(env, jstr, local_string);
    return 1;
}
/** Add obj to GList *list.
 * Returns 1.
 * Returns 0 and throws if anything fail.
 */
static int
add_to_list(JNIEnv* env, GList** list, jobject obj, OutConverter convert) {
    gpointer data = NULL;

    g_error_if_fail(env && list && convert);
    lasso_return_val_if_fail(convert(env, obj, &data), 0);
    if (data)
        *list = g_list_append(*list, data);
    return 1;
}

/* Ghash table handling impl */
/** Create a java array from a GHashTable, using the convert function. */
static int
get_hash(JNIEnv *env, char *clsName, GHashTable *hashtable, Converter convert, jobjectArray *jarr)
{
    jsize l = 0, i = 0;

    GList *keys = NULL, *values = NULL;
    int ret = 1;

    g_error_if_fail (env && hashtable && convert);
    l = g_hash_table_size(hashtable);
    lasso_return_val_if_fail(create_object_array(env, clsName, 2*l, jarr), 0);
    keys = g_hash_table_get_keys(hashtable);
    values = g_hash_table_get_values(hashtable);
    if (! (keys && values)) {
        ret = 0;
        exception(env, "cannot allocate for converting GHashTable to an array");
        goto out;
    }
    for (i=0; i < 2*l && keys && values; i+=2) {
        jstring key = NULL;
        jobject value = NULL;

        if (! (string_to_jstring(env, (char*)keys->data, &key)
               && convert(env, (gpointer)values->data, &value)
               && set_array_element(env, *jarr, i, key)
               && set_array_element(env, *jarr, i+1, value))) {
               ret = 0;
               goto out;
        }
        keys = g_list_next(keys);
        values = g_list_next(values);
    }
out:
    if (keys)
        g_list_free(keys);
    if (values)
        g_list_free(values);
    return ret;
}
/** Fill a GHashTable with content of java array arr.
 * Even indexed element coressponds to keys (jstring) and
 * odd indexed one to value (GObject).
 * Returns 1.
 * Returns 0 and thows an exception if anything fail.
 */
static int
set_hash_of_objects(JNIEnv *env, GHashTable *hashtable, jobjectArray jarr)
{
    jsize l = 0, i = 0;

    g_error_if_fail (env && hashtable);
    if (jarr) {
        /** First increment ref count of object in jarr */
        lasso_return_val_if_fail(get_array_size(env, jarr, &l), 0);
        if (l % 2 != 0) {
            exception(env, "java array not of an even size");
            return 0;
        }
        for (i = 1; i < l; i += 2) {
            jobject jobj = NULL;
            GObject *gobj = NULL;

            lasso_return_val_if_fail(get_array_element(env, jarr, i, &jobj), 0);
            lasso_return_val_if_fail(jobject_to_gobject_noref(env, jobj, &gobj), 0);
            (*env)->DeleteLocalRef(env, jobj);
        }
        /* increment ref count of objects */
        for (i = 1; i < l; i += 2) {
            jobject jobj = NULL;
            GObject *gobj = NULL;

            get_array_element(env, jarr, i, &jobj);
            jobject_to_gobject(env, jobj, &gobj);
            (*env)->DeleteLocalRef(env, jobj);
        }
    }
    /** Remove old values, if hashtable is well initialized
     * it should unref objects automatically. */
    g_hash_table_remove_all(hashtable);
    /** Insert new values */
    if (jarr) {
        for (i = 0; i < l; i += 2) {
            jstring jkey = NULL;
            char *key = NULL;
            jobject jvalue = NULL;
            GObject *value = NULL;

            lasso_return_val_if_fail(get_array_element(env, jarr, i, &jkey), 0);
            lasso_return_val_if_fail(get_array_element(env, jarr, i+1, &jvalue), 0);
            lasso_return_val_if_fail(jstring_to_string(env, jkey, &key), 0);
            if (! jobject_to_gobject_noref(env, jvalue, &value)) {
                if (key)
                    g_free(key);
                g_hash_table_remove_all(hashtable);
                return 0;
            }
            g_hash_table_insert (hashtable, key, value);
            (*env)->DeleteLocalRef(env, jkey);
            (*env)->DeleteLocalRef(env, jvalue);
        }
    }
    return 1;
}
/** Insert a java String array, containing
 * keys at odd indexes, and values at even indexes into an existing
 * GHashTable. Old entries are lost, but hopefully deallocated by
 * the hashtable free functions --- setted at creation, see GLib
 * documentation.
 *
 * @param env the JNI context given by the JVM
 * @param hashtable an existing GHashTable
 * @param a ref to a java object Array of size multiple of two
 *
 * @return 1 if successful, 0 if anything bad happen.
 */
static int
set_hash_of_strings(JNIEnv *env, GHashTable *hashtable, jobjectArray jarr) {
    jsize l = 0, i = 0;

    g_error_if_fail (env && hashtable);

    g_hash_table_remove_all(hashtable);
    if (jarr) {
        lasso_return_val_if_fail(get_array_size(env, jarr, &l), 0);
        if (l % 2 != 0) {
            exception(env, "java array not of an even size");
            return 0;
        }
        for (i = 0; i < l; i += 2) {
            jstring jkey = NULL;
            char *key = NULL;
            jstring jvalue = NULL;
            char *value = NULL;

            lasso_return_val_if_fail(get_array_element(env, jarr, i, &jkey)
                                 && get_array_element(env, jarr, i+1, &jvalue)
                                 && jstring_to_string(env, jkey, &key), 0);
            if (! key) {
                exception(env, "key is null");
                return 0;
            }
            if (! jstring_to_string(env, jvalue, &value)) {
                if (key)
                    g_free(key);
                g_hash_table_remove_all(hashtable);
                return 0;
            }
            /* Can use insert because hash table is empty */
            g_hash_table_insert(hashtable, key, value);
            (*env)->DeleteLocalRef(env, jkey);
            (*env)->DeleteLocalRef(env, jvalue);
        }
    }
    return 1;
}

/** Remove the value for the given key from hashtable. */
static int
remove_from_hash(JNIEnv *env, GHashTable *hashtable, jstring jkey) {
    const char *key = NULL;

    g_error_if_fail (env && hashtable);

    lasso_return_val_if_fail(jstring_to_local_string(env, jkey, &key), 0);
    g_hash_table_remove(hashtable, key);
    release_local_string(env, jkey, key);
    return 1;
}
/** Add a jobject to an hashtable */
static int
add_to_hash(JNIEnv *env, GHashTable *hashtable, jstring jkey, jobject jvalue, OutConverter convert, GFunc free_function)
{
    void *value = NULL;
    char *key = NULL;

    g_error_if_fail (env && hashtable && key && convert);

    if (! (convert(env, jvalue, &value)
           && jstring_to_string(env, jkey, &key)))
           goto error;

    g_hash_table_replace(hashtable, key, value);
    return 1;
error:
    if (key)
        g_free(key);
    if (value)
        free_function(value, NULL);
    return 0;
}
static int
get_hash_by_name(JNIEnv *env, GHashTable *hashtable, jstring jkey, Converter convert, jobject *jvalue)
{
    const char *key = NULL;
    gpointer value = NULL;

    g_error_if_fail (env && hashtable && convert);

    lasso_return_val_if_fail(jstring_to_local_string(env, jkey, &key), 0);
    value = g_hash_table_lookup(hashtable, key);
    release_local_string(env, jkey, key);
    return convert(env, value, jvalue);
}
static void
throw_by_name(JNIEnv *env, const char *name, const char *msg)
{
    jclass cls = (*env)->FindClass(env, name);
    /* if cls is NULL, an exception has already been thrown */
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, msg);
    }
    /* free the local ref */
    (*env)->DeleteLocalRef(env, cls);
}


/* JNI Functions */
JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoJNI_init2(JNIEnv *env, jclass cls) {
    lasso_wrapper_key = g_quark_from_static_string("JavaLasso::wrapper");
}
JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoJNI_destroy(JNIEnv *env, jclass cls, jlong cptr) {
    GObject *obj = (GObject*)(ptrdiff_t)cptr;
    set_shadow_object(env, obj, NULL);
    g_object_unref(obj);
}
JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoJNI_set_1shadow_1object(JNIEnv *env, jclass cls, jlong cptr, jobject shadow_object) {
    GObject *gobj = NULL;

    gobj = convert_jlong_to_gobject(cptr);
    set_shadow_object(env, gobj, shadow_object);
}
