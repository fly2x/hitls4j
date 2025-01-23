#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "org_openhitls_crypto_core_hash_MessageDigest.h"

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

static void throwException(JNIEnv *env, const char *message) {
    jclass exceptionClass = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, message);
    }
}

static void bslInit(void) {
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);
}

static void initBSL(void) {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, bslInit);
}

static CRYPT_MD_AlgId getAlgorithmId(const char *algorithm) {
    if (strcmp(algorithm, "SHA-1") == 0) return CRYPT_MD_SHA1;
    if (strcmp(algorithm, "SHA-224") == 0) return CRYPT_MD_SHA224;
    if (strcmp(algorithm, "SHA-256") == 0) return CRYPT_MD_SHA256;
    if (strcmp(algorithm, "SHA-384") == 0) return CRYPT_MD_SHA384;
    if (strcmp(algorithm, "SHA-512") == 0) return CRYPT_MD_SHA512;
    if (strcmp(algorithm, "SHA3-224") == 0) return CRYPT_MD_SHA3_224;
    if (strcmp(algorithm, "SHA3-256") == 0) return CRYPT_MD_SHA3_256;
    if (strcmp(algorithm, "SHA3-384") == 0) return CRYPT_MD_SHA3_384;
    if (strcmp(algorithm, "SHA3-512") == 0) return CRYPT_MD_SHA3_512;
    if (strcmp(algorithm, "SM3") == 0) return CRYPT_MD_SM3;
    return CRYPT_MD_MAX;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_MessageDigest_nativeInit
  (JNIEnv *env, jobject obj, jstring algorithm) {
    initBSL();

    const char *algoStr = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (algoStr == NULL) {
        throwException(env, "Failed to get algorithm string");
        return;
    }

    CRYPT_MD_AlgId algoId = getAlgorithmId(algoStr);
    if (algoId == CRYPT_MD_MAX) {
        (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
        throwException(env, "Unknown algorithm");
        return;
    }

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(algoId);
    if (ctx == NULL) {
        (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
        throwException(env, "Failed to create message digest context");
        return;
    }

    if (CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
        throwException(env, "Failed to initialize message digest");
        return;
    }

    // Store ctx pointer in Java object
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    (*env)->SetLongField(env, obj, fid, (jlong)ctx);

    (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_MessageDigest_nativeUpdate
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
        throwException(env, "Failed to update message digest");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_hash_MessageDigest_nativeDoFinal
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "Invalid context");
        return NULL;
    }
    
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, "getDigestLength", "()I");
    if (mid == NULL) {
        throwException(env, "Failed to get digest length method");
        return NULL;
    }
    
    jint digestLen = (*env)->CallIntMethod(env, obj, mid);
    unsigned char hash[128];  // Large enough for any hash
    uint32_t outLen = digestLen;
    
    if (CRYPT_EAL_MdFinal(ctx, hash, &outLen) != CRYPT_SUCCESS) {
        throwException(env, "Failed to finalize message digest");
        return NULL;
    }
    
    jbyteArray result = (*env)->NewByteArray(env, digestLen);
    if (result == NULL) {
        throwException(env, "Failed to create result array");
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, result, 0, digestLen, (jbyte *)hash);
    return result;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_hash_MessageDigest_nativeFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_hash_MessageDigest_getContextPtr
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    return (*env)->GetLongField(env, obj, fid);
}
