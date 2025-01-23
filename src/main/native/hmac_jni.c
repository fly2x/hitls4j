#include <jni.h>
#include <stdlib.h>
#include <stdio.h>
#include <include/crypt_errno.h>
#include <include/crypt_algid.h>
#include <include/crypt_eal_mac.h>
#include <include/bsl_sal.h>
#include <include/bsl_err.h>
#include "org_openhitls_crypto_core_mac_HMAC.h"

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
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

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeInit
  (JNIEnv *env, jobject obj, jint algorithm, jbyteArray key) {
    initBSL();
    // Verify algorithm is supported
    if (!CRYPT_EAL_MacIsValidAlgId(algorithm)) {
        throwException(env, "Unsupported HMAC algorithm");
        return 0;
    }
    
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algorithm);
    if (ctx == NULL) {
        throwException(env, "Failed to create HMAC context");
        return 0;
    }

    jbyte *keyBytes = NULL;
    jsize keyLen = 0;
    
    if (key != NULL) {
        keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
        if (keyBytes == NULL) {
            CRYPT_EAL_MacFreeCtx(ctx);
            throwException(env, "Failed to get key bytes");
            return 0;
        }
        keyLen = (*env)->GetArrayLength(env, key);
    }
    
    int result = CRYPT_EAL_MacInit(ctx, (uint8_t *)keyBytes, keyLen);
    if (result != CRYPT_SUCCESS) {
        if (keyBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        }
        CRYPT_EAL_MacFreeCtx(ctx);
        throwException(env, "Failed to initialize HMAC");
        return 0;
    }

    if (keyBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    }
    
    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeUpdate
  (JNIEnv *env, jobject obj, jlong contextPtr, jbyteArray data, jint offset, jint length) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "HMAC context is null");
        return;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        throwException(env, "Failed to get data bytes");
        return;
    }

    int result = CRYPT_EAL_MacUpdate(ctx, (uint8_t *)(bytes + offset), length);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    
    if (result != CRYPT_SUCCESS) {
        throwException(env, "Failed to update HMAC");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeDoFinal
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "HMAC context is null");
        return NULL;
    }

    uint32_t macLen = CRYPT_EAL_GetMacLen(ctx);
    if (macLen == 0) {
        throwException(env, "Invalid MAC length");
        return NULL;
    }

    uint8_t *mac = malloc(macLen);
    if (mac == NULL) {
        throwException(env, "Failed to allocate memory for MAC");
        return NULL;
    }

    uint32_t outLen = macLen;
    int result = CRYPT_EAL_MacFinal(ctx, mac, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(mac);
        throwException(env, "Failed to finalize HMAC");
        return NULL;
    }
    
    jbyteArray result_array = (*env)->NewByteArray(env, macLen);
    if (result_array == NULL) {
        free(mac);
        throwException(env, "Failed to create result array");
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, result_array, 0, macLen, (jbyte *)mac);
    free(mac);

    return result_array;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeReinit
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "HMAC context is null");
        return;
    }

    int result = CRYPT_EAL_MacReinit(ctx);
    if (result != CRYPT_SUCCESS) {
        throwException(env, "Failed to reinitialize HMAC");
        return;
    }
}

JNIEXPORT jint JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeGetMacLength
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "HMAC context is null");
        return 0;
    }

    uint32_t macLen = CRYPT_EAL_GetMacLen(ctx);
    if (macLen == 0) {
        throwException(env, "Invalid MAC length");
        return 0;
    }

    return (jint)macLen;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
        CRYPT_EAL_MacFreeCtx(ctx);
    }
}