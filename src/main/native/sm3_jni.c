#include <jni.h>
#include <stdlib.h>
#include <include/crypt_errno.h>
#include <include/crypt_eal_md.h>
#include "org_openhitls_crypto_core_hash_SM3.h"

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

static void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
}

static void throwException(JNIEnv *env, const char *message) {
    jclass exceptionClass = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, message);
    }
}

static void bslInit() {
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);
}

static void initBSL() {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, bslInit);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_SM3_nativeInit
  (JNIEnv *env, jobject obj) {
    initBSL();
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    if (ctx == NULL) {
        throwException(env, "Failed to create SM3 context");
        return;
    }
    
    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        throwException(env, "Failed to initialize SM3 context");
        return;
    }
    
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    (*env)->SetLongField(env, obj, fid, (jlong)ctx);
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_hash_SM3_getContextPtr
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    return (*env)->GetLongField(env, obj, fid);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_SM3_nativeUpdate
  (JNIEnv *env, jobject obj, jlong contextPtr, jbyteArray data, jint offset, jint length) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "Invalid context");
        return;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        throwException(env, "Failed to get byte array elements");
        return;
    }

    int result = CRYPT_EAL_MdUpdate(ctx, (unsigned char *)(bytes + offset), length);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    
    if (result != CRYPT_SUCCESS) {
        throwException(env, "Failed to update SM3 context");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_hash_SM3_nativeDoFinal
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "Invalid context");
        return NULL;
    }

    unsigned char hash[32];
    uint32_t outLen = sizeof(hash);
    
    if (CRYPT_EAL_MdFinal(ctx, hash, &outLen) != CRYPT_SUCCESS) {
        throwException(env, "Failed to finalize SM3 hash");
        return NULL;
    }
    
    jbyteArray result = (*env)->NewByteArray(env, 32);
    if (result == NULL) {
        throwException(env, "Failed to create result array");
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, result, 0, 32, (jbyte *)hash);
    return result;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_SM3_nativeFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}