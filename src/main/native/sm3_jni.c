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
        return;
    }
    
    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        return;
    }
    
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    (*env)->SetLongField(env, obj, fid, (jlong)ctx);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_SM3_nativeUpdate
  (JNIEnv *env, jobject obj, jbyteArray data, jint offset, jint length) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)(*env)->GetLongField(env, obj, fid);
    
    if (ctx == NULL) {
        return;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        return;
    }

    int result = CRYPT_EAL_MdUpdate(ctx, (unsigned char *)(bytes + offset), length);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    
    if (result != CRYPT_SUCCESS) {
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_hash_SM3_nativeDoFinal
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)(*env)->GetLongField(env, obj, fid);
    
    if (ctx == NULL) {
        return NULL;
    }

    unsigned char hash[32];
    uint32_t outLen = sizeof(hash);
    
    if (CRYPT_EAL_MdFinal(ctx, hash, &outLen) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        (*env)->SetLongField(env, obj, fid, 0L);
        return NULL;
    }
    
    jbyteArray result = (*env)->NewByteArray(env, 32);
    if (result == NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
        (*env)->SetLongField(env, obj, fid, 0L);
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, result, 0, 32, (jbyte *)hash);

    CRYPT_EAL_MdFreeCtx(ctx);
    (*env)->SetLongField(env, obj, fid, 0L);

    return result;
}