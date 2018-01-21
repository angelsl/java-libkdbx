#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <jni.h>
#include <tomcrypt.h>

#include "kdbxouter.h"

static inline jclass load_class(JNIEnv *jenv, const char *clsname) {
    jclass jcls = (*jenv)->FindClass(jenv, clsname);
    if (jcls) {
        jclass gjcls = (*jenv)->NewGlobalRef(jenv, jcls);
        if (gjcls) {
            return gjcls;
        }
    }
    return NULL;
}

static inline void throw(JNIEnv *jenv, const char *msg) {
    static jclass cls_KDBXException = NULL;
    if (!cls_KDBXException) {
        cls_KDBXException = load_class(jenv, "io/github/angelsl/java/libkdbx/KDBXException");
    }
    if (!cls_KDBXException) {
        (*jenv)->FatalError(jenv, msg);
    } else {
        (*jenv)->ThrowNew(jenv, cls_KDBXException, msg);
    }
}

JNIEXPORT jbyteArray JNICALL Java_io_github_angelsl_java_libkdbx_Crypto_sha256Native(JNIEnv *, jclass, jobjectArray);
JNIEXPORT jbyteArray JNICALL Java_io_github_angelsl_java_libkdbx_Crypto_sha256Native
    (JNIEnv *jenv, jclass cls, jobjectArray jkeys) {
    hash_state md = { 0 };
    if (sha256_init(&md) != CRYPT_OK) {
        throw(jenv, "SHA256 init failed");
        return NULL;
    }

    jsize len = (*jenv)->GetArrayLength(jenv, jkeys);
    for (jsize i = 0; i < len; ++i) {
        jbyteArray jkey = (*jenv)->GetObjectArrayElement(jenv, jkeys, i);
        if (!jkey) {
            throw(jenv, "Failed to get key array");
            return NULL;
        }

        jboolean iscopy = 1;
        jsize keysz = (*jenv)->GetArrayLength(jenv, jkey);
        void *key = (*jenv)->GetPrimitiveArrayCritical(jenv, jkey, &iscopy);
        if (!key) {
            throw(jenv, "Failed to get key array data");
            return NULL;
        }
        int fail = sha256_process(&md, key, keysz) != CRYPT_OK;
        if (iscopy) {
            memset(key, 0, keysz);
        }
        (*jenv)->ReleasePrimitiveArrayCritical(jenv, jkey, key, 0);
        if (fail) {
            throw(jenv, "SHA256 process failed");
            return NULL;
        }
    }

    unsigned char hash_stack[32] = { 0 };
    if (sha256_done(&md, hash_stack) != CRYPT_OK) {
        throw(jenv, "SHA256 termination failed");
        return NULL;
    }

    jbyteArray jhash = (*jenv)->NewByteArray(jenv, 32);
    if (!jhash) {
        throw(jenv, "Failed to create result array");
        ZERO_ARRAY(hash_stack);
        return NULL;
    }
    void *hash = (*jenv)->GetPrimitiveArrayCritical(jenv, jhash, NULL);
    if (hash) {
        memcpy(hash, hash_stack, 32);
        (*jenv)->ReleasePrimitiveArrayCritical(jenv, jhash, hash, 0);
    }
    ZERO_ARRAY(hash_stack);
    if (!hash) {
        throw(jenv, "Failed to get result array data");
        return NULL;
    }
    return jhash;
}

JNIEXPORT void JNICALL Java_io_github_angelsl_java_libkdbx_KDBXIRS_applyNative(JNIEnv *, jobject, jbyteArray);
JNIEXPORT void JNICALL Java_io_github_angelsl_java_libkdbx_KDBXIRS_applyNative
    (JNIEnv *jenv, jobject this, jbyteArray jtext) {
    throw(jenv, "Not implemented");
}

JNIEXPORT void JNICALL Java_io_github_angelsl_java_libkdbx_format_KDBXOuter_initNative(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_io_github_angelsl_java_libkdbx_format_KDBXOuter_initNative(JNIEnv *jenv, jclass cls) {
    (void) jenv; (void) cls;
    kdbxo_crypto_init();
}

JNIEXPORT jobject JNICALL Java_io_github_angelsl_java_libkdbx_format_KDBXOuter_parseNative(JNIEnv *, jclass, jbyteArray, jbyteArray);
JNIEXPORT jobject JNICALL Java_io_github_angelsl_java_libkdbx_format_KDBXOuter_parseNative
    (JNIEnv *jenv, jclass cls, jbyteArray jin, jbyteArray jkey32) {
    kdbxo_read_result *rr = NULL;

    size_t insz = (*jenv)->GetArrayLength(jenv, jin);
    void *in = (*jenv)->GetByteArrayElements(jenv, jin, NULL);
    if (!in) {
        throw(jenv, "Failed to retrieve Java array contents");
        return NULL;
    }

    jboolean key32_copied = 1;
    void *key32 = (*jenv)->GetByteArrayElements(jenv, jkey32, &key32_copied);
    if (!key32) {
        throw(jenv, "Failed to retrieve Java array contents");
        goto fail;
    }

    kdbxo_result r = kdbxo_unwrap(in, insz, key32, &rr);
    if (key32_copied) { memset(key32, 0, 32); }
    (*jenv)->ReleaseByteArrayElements(jenv, jkey32, key32, JNI_ABORT);
    if (r || !rr) {
        throw(jenv, kdbxo_error ? kdbxo_error : "no error specified");
        goto fail;
    }

    static jclass cls_NativeResult = NULL;
    if (!cls_NativeResult) { cls_NativeResult = load_class(jenv, "io/github/angelsl/java/libkdbx/format/KDBXOuter$NativeResult"); }
    if (!cls_NativeResult) {
        throw(jenv, "Failed to load NativeResult class");
        goto fail;
    }

    static jclass cls_bytearray = NULL;
    if (!cls_bytearray) { cls_bytearray = load_class(jenv, "[B"); }
    if (!cls_bytearray) {
        throw(jenv, "Failed to load byte[] class");
        goto fail;
    }

    static jmethodID ctor = NULL;
    if (!ctor) { ctor = (*jenv)->GetMethodID(jenv, cls_NativeResult, "<init>", "()V"); }
    if (!ctor) {
        throw(jenv, "Failed to access NativeResult constructor");
        goto fail;
    }

    jobject jobj = (*jenv)->NewObject(jenv, cls_NativeResult, ctor);
    if (!jobj) {
        throw(jenv, "Failed to construct NativeResult");
        goto fail;
    }

    static jfieldID jf_xml = NULL, jf_irs = NULL, jf_irsKey = NULL,
                    jf_binaries = NULL, jf_binariesProtection = NULL;
    if (!jf_xml) { jf_xml = (*jenv)->GetFieldID(jenv, cls_NativeResult, "xml", "[B"); }
    if (!jf_irs) { jf_irs = (*jenv)->GetFieldID(jenv, cls_NativeResult, "irs", "I"); }
    if (!jf_irsKey) { jf_irsKey = (*jenv)->GetFieldID(jenv, cls_NativeResult, "irsKey", "[B"); }
    if (!jf_binaries) { jf_binaries = (*jenv)->GetFieldID(jenv, cls_NativeResult, "binaries", "[[B"); }
    if (!jf_binariesProtection) { jf_binariesProtection = (*jenv)->GetFieldID(jenv, cls_NativeResult, "binariesProtection", "[Z"); }
    if (!jf_xml || !jf_irs || !jf_irsKey || !jf_binaries || !jf_binariesProtection) {
        throw(jenv, "Failed to load NativeResult fields");
        goto fail;
    }

    jbyteArray jp_xml = (*jenv)->NewByteArray(jenv, rr->xmlsz),
               jp_irsKey = (*jenv)->NewByteArray(jenv, rr->irs_key_sz);
    jbooleanArray jp_binariesProtection = (*jenv)->NewBooleanArray(jenv, rr->binarysz);
    jobjectArray jp_binaries = (*jenv)->NewObjectArray(jenv, rr->binarysz, cls_bytearray, NULL);
    if (!jp_xml || !jp_irsKey || !jp_binariesProtection || !jp_binaries) {
        throw(jenv, "Failed to construct NativeResult arrays");
        goto fail;
    }

    void *jr_xml = (*jenv)->GetPrimitiveArrayCritical(jenv, jp_xml, NULL);
    if (jr_xml) {
        memcpy(jr_xml, rr->xml, rr->xmlsz);
        (*jenv)->ReleasePrimitiveArrayCritical(jenv, jp_xml, jr_xml, 0);
    }

    void *jr_irsKey = (*jenv)->GetPrimitiveArrayCritical(jenv, jp_irsKey, NULL);
    if (jr_irsKey) {
        memcpy(jr_irsKey, rr->irs_key, rr->irs_key_sz);
        (*jenv)->ReleasePrimitiveArrayCritical(jenv, jp_irsKey, jr_irsKey, 0);
    }

    uint8_t *jr_binariesProtection = (*jenv)->GetPrimitiveArrayCritical(jenv, jp_binariesProtection, NULL);
    if (jr_binariesProtection) {
        for (size_t i = 0; i < rr->binarysz; ++i) {
            jr_binariesProtection[i] = !!rr->binary[i].prot;
        }
        (*jenv)->ReleasePrimitiveArrayCritical(jenv, jp_binariesProtection, jr_binariesProtection, 0);
    }

    if (!jr_xml || !jr_irsKey || !jr_binariesProtection) {
        throw(jenv, "Failed to populate NativeResult arrays");
        goto fail;
    }

    for (size_t i = 0; i < rr->binarysz; ++i) {
        kdbxo_binary *bin = rr->binary + i;
        jbyteArray arr = (*jenv)->NewByteArray(jenv, bin->datasz);
        if (!arr) {
            throw(jenv, "Failed to create array for binary");
            goto fail;
        }
        void *arrdata = (*jenv)->GetPrimitiveArrayCritical(jenv, arr, NULL);
        if (!arrdata) {
            throw(jenv, "Failed to populate array for binary");
            goto fail;
        }
        memcpy(arrdata, bin->data, bin->datasz);
        (*jenv)->ReleasePrimitiveArrayCritical(jenv, arr, arrdata, 0);
        (*jenv)->SetObjectArrayElement(jenv, jp_binaries, i, arr);
    }

    (*jenv)->SetIntField(jenv, jobj, jf_irs, (jint) rr->irs);
    (*jenv)->SetObjectField(jenv, jobj, jf_xml, jp_xml);
    (*jenv)->SetObjectField(jenv, jobj, jf_irsKey, jp_irsKey);
    (*jenv)->SetObjectField(jenv, jobj, jf_binaries, jp_binaries);
    (*jenv)->SetObjectField(jenv, jobj, jf_binariesProtection, jp_binariesProtection);

end:
    if (rr) {
        kdbxo_free_read_result(rr);
    }
    (*jenv)->ReleaseByteArrayElements(jenv, jin, in, JNI_ABORT);
    return jobj;
fail:
    jobj = NULL;
    goto end;
}
