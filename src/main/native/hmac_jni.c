#include <jni.h>
#include <stdlib.h>
#include <string.h>
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

// Get algorithm ID from algorithm name
static int getAlgorithmId(const char *algorithm) {
    if (strcmp(algorithm, "HMACSHA224") == 0) {
        return CRYPT_MAC_HMAC_SHA224;
    } else if (strcmp(algorithm, "HMACSHA256") == 0) {
        return CRYPT_MAC_HMAC_SHA256;
    } else if (strcmp(algorithm, "HMACSHA384") == 0) {
        return CRYPT_MAC_HMAC_SHA384;
    } else if (strcmp(algorithm, "HMACSHA512") == 0) {
        return CRYPT_MAC_HMAC_SHA512;
    } else if (strcmp(algorithm, "HMACSM3") == 0) {
        return CRYPT_MAC_HMAC_SM3;
    }
    return -1;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeInit
  (JNIEnv *env, jobject obj, jstring jalgorithm, jbyteArray key) {
    initBSL();

    // Convert Java string to C string
    const char *algorithm = (*env)->GetStringUTFChars(env, jalgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, "Failed to get algorithm string");
        return 0;
    }

    // Get algorithm ID
    int algorithmId = getAlgorithmId(algorithm);
    (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);

    if (algorithmId == -1) {
        throwException(env, "Unsupported HMAC algorithm");
        return 0;
    }

    // Verify algorithm is supported
    if (!CRYPT_EAL_MacIsValidAlgId(algorithmId)) {
        throwException(env, "Invalid HMAC algorithm");
        return 0;
    }
    
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algorithmId);
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

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throwException(env, "Failed to get data bytes");
        return;
    }

    int result = CRYPT_EAL_MacUpdate(ctx, (uint8_t *)dataBytes + offset, length);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (result != CRYPT_SUCCESS) {
        throwException(env, "Failed to update HMAC");
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeDoFinal
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "HMAC context is null");
        return NULL;
    }

    uint32_t macLength = CRYPT_EAL_GetMacLen(ctx);
    if (macLength == 0) {
        throwException(env, "Failed to get MAC length");
        return NULL;
    }

    uint8_t *mac = malloc(macLength);
    if (mac == NULL) {
        throwException(env, "Failed to allocate memory for MAC");
        return NULL;
    }

    uint32_t outLen = macLength;
    int result = CRYPT_EAL_MacFinal(ctx, mac, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(mac);
        throwException(env, "Failed to finalize HMAC");
        return NULL;
    }

    jbyteArray macArray = (*env)->NewByteArray(env, outLen);
    if (macArray == NULL) {
        free(mac);
        throwException(env, "Failed to create Java byte array");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, macArray, 0, outLen, (jbyte *)mac);
    free(mac);

    return macArray;
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
    }
}

JNIEXPORT jint JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeGetMacLength
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, "HMAC context is null");
        return 0;
    }

    return CRYPT_EAL_GetMacLen(ctx);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_mac_HMAC_nativeFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MacFreeCtx((CRYPT_EAL_MacCtx *)contextPtr);
    }
}