#include <lasso/lasso.h>
#include <lasso_config.h>
#include <jni.h>
#include "com_entrouvert_lasso_LassoJNI.h"
#include <string.h>

static GQuark lasso_wrapper_key;
typedef jobject (*Converter)(JNIEnv *env, void *);
typedef void *(*OutConverter)(JNIEnv *env, jobject);

/* String handling */
static jstring string_to_jstring(JNIEnv *env, const char *str);
static jstring string_to_jstring_and_free(JNIEnv *env, char *str);
static const char* jstring_to_string(JNIEnv *env, jstring str);
static void release_utf_string(JNIEnv *env, jstring str, const char *utfstr);

/* xmlNode handling */
static jstring xml_node_to_jstring(JNIEnv *env, xmlNode *xmlnode);
static xmlNode* jstring_to_xml_node(JNIEnv *env, jstring string);

/* Lasso object handling */
/* Reference counting: 
 *
 * new jobject make ++refcount
 *
 */

static GObject* jobject_to_gobject(JNIEnv *env, jobject *obj);
static GObject* jobject_to_gobject_and_ref(JNIEnv *env, jobject *obj);
static jobject gobject_to_jobject(JNIEnv *env, GObject *obj);
static jobject gobject_to_jobject_and_ref(JNIEnv *env, GObject *obj);

/* List handling */
static void free_glist(GList **list, GFunc free_function) ;
static jobjectArray get_list(JNIEnv *, char *,GList *, Converter);
#define get_list_of_strings(env,list) get_list(env,"java/lang/String",list,(Converter)string_to_jstring)
#define get_list_of_xml_nodes(env,list) get_list(env,"java/lang/String",list,(Converter)xml_node_to_jstring)
#define get_list_of_objects(env,list) get_list(env,"java/lang/Object",list,(Converter)gobject_to_jobject_and_ref)
static void set_list(JNIEnv*,GList **, jobjectArray jarr,GFunc free_function, OutConverter);
#define set_list_of_strings(env,list,jarr) set_list(env,list,jarr,(GFunc)g_free,(OutConverter)jstring_to_string)
#define set_list_of_xml_nodes(env,list,jarr) set_list(env,list,jarr,(GFunc)xmlFreeNode,(OutConverter)jstring_to_xml_node)
#define set_list_of_objects(env,list,jarr) set_list(env,list,jarr,(GFunc)g_object_unref,(OutConverter)jobject_to_gobject_and_ref)
static void remove_from_list(JNIEnv*,GList**,jobject,GFunc,GCompareFunc,OutConverter);
#define remove_from_list_of_strings(env,list,obj) remove_from_list(env,list,obj,(GFunc)g_free,(GCompareFunc)strcmp,(OutConverter)jstring_to_string)
#define remove_from_list_of_xml_nodes(env,list,obj) remove_from_list(env,list,obj,(GFunc)xmlFreeNode,(GCompareFunc)strcmp,(OutConverter)jstring_to_xml_node)
#define remove_from_list_of_objects(env,list,obj) remove_from_list(env,list,obj,(GFunc)g_object_unref,(GCompareFunc)strcmp,(OutConverter)jobject_to_gobject_and_ref)
static void add_to_list(JNIEnv*,GList**,void *,OutConverter);
#define add_to_list_of_strings(env,list,obj) add_to_list(env,list,obj,(OutConverter)jstring_to_string)
#define add_to_list_of_xml_nodes(env,list,obj) add_to_list(env,list,obj,(OutConverter)jstring_to_xml_node)
#define add_to_list_of_objects(env,list,obj) add_to_list(env,list,obj,(OutConverter)jobject_to_gobject_and_ref)

/* hashtable handling */
/* Use property array cell[i % 2 = 0] = keys and cell[i % 2 = 1] = values  */
static jobjectArray get_hash(JNIEnv *env, char *clsName, GHashTable *hashtable, Converter convert);
#define get_hash_of_strings(env,hash) get_hash(env,"java/lang/String",hash,(Converter)string_to_jstring)
#define get_hash_of_objects(env,hash) get_hash(env,"java/lang/String",hash,(Converter)gobject_to_jobject_and_ref)
static void set_hash(JNIEnv *env, GHashTable *hashtable, jobjectArray arr, OutConverter convert);
#define set_hash_of_strings(env,hash,arr) set_hash(env,hash,arr,(OutConverter)jstring_to_string)
#define set_hash_of_objects(env,hash,arr) set_hash(env,hash,arr,(OutConverter)jobject_to_gobject_and_ref)
static void remove_from_hash(JNIEnv *env, GHashTable *hashtable, jstring key);
#define remove_from_hash_of_strings(env,hash,key) remove_from_hash(env,hash,key)
#define remove_from_hash_of_objects(env,hash,key) remove_from_hash(env,hash,key)
static void add_to_hash(JNIEnv *env, GHashTable *hashtable, jstring key, jobject obj, OutConverter convert);
#define add_to_hash_of_strings(env,hash,key,obj) add_to_hash(env,hash,key,obj,(OutConverter)jstring_to_string)
#define add_to_hash_of_objects(env,hash,key,obj) add_to_hash(env,hash,key,obj,(OutConverter)jobject_to_gobject_and_ref)
static jobject get_hash_by_name(JNIEnv *env, GHashTable *hashtable, jstring key, Converter convert);
#define get_hash_of_strings_by_name(end,hash,key) get_hash_by_name(end,hash,key,(Converter)string_to_jstring)
#define get_hash_of_objects_by_name(end,hash,key) get_hash_by_name(end,hash,key,(Converter)gobject_to_jobject_and_ref)



/* utility functions */
static jlong
get_jlong_field(JNIEnv *env, jobject *obj, char *field)
{
    jclass cls;
    jfieldID fid;

    cls = (*env)->GetObjectClass(env, obj);
    if (cls == NULL)
        return 0;
    fid = (*env)->GetFieldID(env, cls, field, "J");
    if (fid == NULL)
        return 0;
    return (*env)->GetLongField(env, obj, fid);
}

static jclass
get_jclass_by_name(JNIEnv *env, char *name) {
    return (*env)->FindClass(env,name);
}

/* string handling impl */
static jstring
string_to_jstring(JNIEnv *env, const char* str)
{
    if (str)
        return (*env)->NewStringUTF(env, str);
    else
        return NULL;
}

static jstring
string_to_jstring_and_free(JNIEnv *env, char* str)
{
    if (str) {
        jstring ret = (*env)->NewStringUTF(env, str);
        g_free(str);
        return ret;
    } else {
        return NULL;
    }
}

static const char *
jstring_to_string(JNIEnv *env, jstring str)
{
    if (str)
        return (*env)->GetStringUTFChars(env, str, NULL);
    else
        return NULL;
}

static const char *
jstring_to_string_dup(JNIEnv *env, jstring jstr)
{
    const char *str = jstring_to_string(env, jstr);
    char * ret = NULL;

    if (! str)
        return NULL;

    ret = g_strdup(str);
    release_utf_string(env, jstr, str);
    return ret;
}

static void
release_utf_string(JNIEnv *env, jstring str, const char *utf_str) {
    if (utf_str && str)
        (*env)->ReleaseStringUTFChars(env, str, utf_str);
}


/* xmlNode handling */
static jstring
xml_node_to_jstring(JNIEnv *env, xmlNode *xmlnode)
{
    xmlOutputBufferPtr buf;

    if (! xmlnode || ! env) {
        return NULL;
    }

    buf = xmlAllocOutputBuffer(NULL);
    if (buf) {
        jstring ret = NULL;
        xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 1, NULL);
        xmlOutputBufferFlush(buf);
        if (buf->conv == NULL) {
            ret = string_to_jstring(env, (char*)buf->buffer->content);
        } else {
            ret = string_to_jstring(env, (char*)buf->conv->content);
        }
        xmlOutputBufferClose(buf);
        return ret;
    } else {
        return NULL;
    }
}

static xmlNode*
jstring_to_xml_node(JNIEnv *env, jstring string) {
    xmlDoc *doc;
    xmlNode *node;
    const char *str;

    str = jstring_to_string(env, string);
    if (str == NULL)
        return NULL;

    doc = xmlReadDoc((unsigned char *)str, NULL, NULL, XML_PARSE_NONET);
    node = xmlDocGetRootElement(doc);
    if (node != NULL) {
        node = xmlCopyNode(node, 1);
    }
    xmlFreeDoc(doc);
    release_utf_string(env, string, str);

    return node;
}

/* lasso objects handling impl */
static jobject
gobject_to_jobject_aux(JNIEnv *env, GObject *obj, gboolean doRef) {
    jobject *self;
#define LASSO_ROOT "com/entrouvert/lasso/"
    if (obj == NULL) {
        return NULL;
    }

    self = (jobject)g_object_get_qdata(obj, lasso_wrapper_key);
    if (self == NULL) {
        jclass nodeCls;
        jmethodID cid;
        char clsName[sizeof(LASSO_ROOT)+50] = LASSO_ROOT;
        const char *typename = G_OBJECT_TYPE_NAME(obj);
        if (! typename) // Moche
            return NULL;
        typename = typename + 5;
        strncpy(clsName+sizeof(LASSO_ROOT)-1, typename,50);    
        clsName[sizeof(LASSO_ROOT)+49] = 0;
        nodeCls = (*env)->FindClass(env, clsName);
        if (nodeCls == NULL) {
            return NULL;
        }
        cid = (*env)->GetMethodID(env, nodeCls, "<init>", "(J)V");
        if (cid == NULL) {
            return NULL;
        }
        self = (*env)->NewObject(env, nodeCls, cid, (jlong)(unsigned int)obj);
        if (self == NULL) {
            return NULL;
        }
        g_object_set_qdata_full(obj, lasso_wrapper_key, self, NULL);
        if (doRef) {
            g_object_ref(obj);
        }
    }
    return self;
}
/** Get or create a new java object encapsulating this lasso GObject, do not increase ref count if created. */
static jobject
gobject_to_jobject(JNIEnv *env, GObject *obj) {
    return gobject_to_jobject_aux(env, obj, FALSE);
}
/** Get or create a new java object encapsulating this lasso GObject, increase ref count if created. */
static jobject
gobject_to_jobject_and_ref(JNIEnv *env, GObject *obj) {
    return gobject_to_jobject_aux(env, obj, TRUE);
}

/** Get the gobject encapsulated by the java object obj */
static GObject* 
jobject_to_gobject(JNIEnv *env, jobject *obj) {
    return (GObject*)(int)get_jlong_field(env, obj, "cptr");
}

/** Get the gobject encapsulated by the java object obj and increase its ref count. The only
 * use for this function is composed with set_list_of_objects or set_hash_of_object. */
static GObject* 
jobject_to_gobject_and_ref(JNIEnv *env, jobject *obj) {
    GObject *ret;

    ret = jobject_to_gobject(env, obj);
    if (ret) {
        g_object_ref(obj);
    }

    return ret;
}
/* List handling */
static void 
free_glist(GList **list, GFunc free_function) {
    if (!list)
        return;
    if (*list) {
        if (free_function) {
            g_list_foreach(*list, free_function, NULL);
        }
        g_list_free(*list);
    }
    if (list)
        *list = NULL;
}

static jobjectArray
get_list(JNIEnv *env, char *clsName, GList *list, Converter convert) {
    jsize l = g_list_length(list),i;
    jobjectArray jarr;
    jclass cls;

    if (!env || !list || !clsName || !convert) {
        return NULL;
    }
    cls = get_jclass_by_name(env, clsName);
    if (!cls) {
        return NULL;
    }

    jarr = (*env)->NewObjectArray(env, l, get_jclass_by_name(env, clsName), NULL);
    if (! jarr) {
        return NULL;
    }

    for (i=0;i<l;i++) {
        jobject item;

        item = convert(env, list->data);
        if ((*env)->ExceptionOccurred(env)) {
            return NULL;
        }
        (*env)->SetObjectArrayElement(env, jarr, i, item);
        if ((*env)->ExceptionOccurred(env)) {
            return NULL;
        }
        list = g_list_next(list);
    }
    return jarr;
}

static void 
set_list(JNIEnv *env, GList **list, jobjectArray jarr, GFunc free_function, OutConverter convert) {
    jobject element;
    jsize size;
    jsize i;

    if (!list || !free_function || !convert || !env)
        return;

    free_glist(list, free_function);
    if (!jarr) {
        *list = NULL;
        return;
    }
    size = (*env)->GetArrayLength(env, jarr);
    for (i=0; i < size; i++) {
        element = (*env)->GetObjectArrayElement(env, jarr, i);
        if ((*env)->ExceptionOccurred(env)) {
            free_glist(list, free_function);
            return;
        }
        *list =  g_list_append(*list, convert(env, element));
    }
}

static void
remove_from_list(JNIEnv *env,GList **list,jobject obj,GFunc free_function,GCompareFunc compare,OutConverter convert) {
    void *c;
    GList *found;

    c = convert(env, obj);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }
    found = g_list_find_custom(*list, c, compare);
    if (found) {
        free_function(found->data, NULL);
        *list = g_list_delete_link(*list, found);
    }
}
static void 
add_to_list(JNIEnv* env,GList** list,jobject obj, OutConverter convert) {
    void *data;

    data = convert(env, obj);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }
    *list = g_list_append(*list, data);
}

struct Aux {
    JNIEnv *env;
    Converter convert;
    gboolean crashed;
    int idx;
    jobjectArray jarr;
};
static void 
get_hash_aux(gpointer key, gpointer data, gpointer udata)
{
    struct Aux *aux = (struct Aux*)udata;
    JNIEnv *env = aux->env;
    jobjectArray jarr = aux->jarr;

    if (! aux->crashed) {
        jstring jkey;
        jobject jvalue;

        jkey = string_to_jstring(env, key);
        if (!jkey) {
            aux->crashed = TRUE;
            return;
        }
        jvalue = aux->convert(env, data);
        if ((*env)->ExceptionOccurred(env)) {
            aux->crashed = TRUE;
            return;
        }
        (*env)->SetObjectArrayElement(env, jarr, aux->idx, jkey);
        if ((*env)->ExceptionOccurred(env)) {
            aux->crashed = TRUE;
            return;
        }
        (*env)->SetObjectArrayElement(env, jarr, aux->idx+1, jvalue);
        if ((*env)->ExceptionOccurred(env)) {
            aux->crashed = TRUE;
            return;
        }
        aux->idx += 2;
    }
}

/* Ghash table handling impl */
/** Set a hash table from an array of size multiple of 2 */
static jobjectArray
get_hash(JNIEnv *env, char *clsName, GHashTable *hashtable,Converter convert)
{
    jsize l;
    jobjectArray jarr;
    jclass cls;
    struct Aux udata = {env, convert, FALSE, 0, NULL };

    if (!env || !hashtable || !clsName || !convert) {
        return NULL;
    }
    l = g_hash_table_size(hashtable);
    cls = get_jclass_by_name(env, clsName);
    if (!cls) {
        return NULL;
    }

    udata.jarr = (*env)->NewObjectArray(env, l, get_jclass_by_name(env, clsName), NULL);
    if (! jarr) {
        return NULL;
    }
    g_hash_table_foreach (hashtable, (GHFunc)get_hash_aux, &udata);
    if (udata.crashed)
        return NULL;
    return udata.jarr;
}
static void set_hash(JNIEnv *env, GHashTable *hashtable, jobjectArray arr, OutConverter convert) {
    jsize l,i;

    if (! env || ! hashtable || ! arr || ! convert)
        return;

    l = (*env)->GetArrayLength(env, arr);
    if ((*env)->ExceptionOccurred(env) || l % 2 != 0) {
        return;
    }
    g_hash_table_remove_all(hashtable);
    for (i = 0; i < l; i += 2) {
        jobject key,item;
        const char *skey;
        void *value;

        key = (*env)->GetObjectArrayElement(env, arr, i);
        if ((*env)->ExceptionOccurred(env)) {
            return;
        }
        item = (*env)->GetObjectArrayElement(env, arr, i);
        if ((*env)->ExceptionOccurred(env)) {
            return;
        }
        value = convert(env, item);
        if ((*env)->ExceptionOccurred(env)) {
            return;
        }
        skey = jstring_to_string(env, (jstring)key);
        if ((*env)->ExceptionOccurred(env)) {
            return;
        }
        g_hash_table_insert(hashtable, g_strdup(skey), value);
        release_utf_string(env, key, skey);
    }
}

static void remove_from_hash(JNIEnv *env, GHashTable *hashtable, jstring key) {
    const char *str;
    if (! env || !hashtable || !key) {
        return;
    }
    str = jstring_to_string(env, key);
    if (!str) {
        return;
    }
    g_hash_table_remove(hashtable, str);
    release_utf_string(env, key, str);
}
static void add_to_hash(JNIEnv *env, GHashTable *hashtable, jstring key, jobject obj, OutConverter convert) 
{
    void *data;
    const char *str;

    if (!env || !hashtable || !key || !obj || !convert) {
        return;
    }
    data = convert(env, obj);
    if ((*env)->ExceptionOccurred(env)) {
        return;
    }
    str = jstring_to_string(env,key);
    if (!str) {
        return;
    }
    g_hash_table_insert(hashtable, g_strdup(str), data);
    release_utf_string(env, key, str);
}
static jobject 
get_hash_by_name(JNIEnv *env, GHashTable *hashtable, jstring key, Converter convert) 
{
    void *data;
    const char *str;

    if (! env || !hashtable || !key || !convert) {
        return NULL;
    }
    str = jstring_to_string(env,key);
    if (!str) {
        return NULL;
    }
    data = g_hash_table_lookup(hashtable,str);
    release_utf_string(env, key, str);
    return convert(env, data);
}

/* JNI Functions */
JNIEXPORT void JNICALL Java_com_entrouvert_lasso_LassoJNI_init2(JNIEnv *env, jclass cls) {
    lasso_wrapper_key = g_quark_from_static_string("JavaLasso::wrapper"); 
}
