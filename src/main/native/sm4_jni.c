#include <jni.h>
#include <stdlib.h>
#include <stdio.h>
#include <include/crypt_errno.h>
#include <include/crypt_algid.h>
#include <include/crypt_eal_cipher.h>
#include <include/bsl_sal.h>
#include <include/bsl_err.h>
#include "org_openhitls_crypto_core_symmetric_SM4.h"

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

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeInit
  (JNIEnv *env, jobject obj, jint algorithm, jbyteArray key, jbyteArray iv, jint mode) {
    initBSL();

    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return;
    }

    CRYPT_EAL_CipherCtx *oldCtx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (oldCtx != NULL) {
        CRYPT_EAL_CipherFreeCtx(oldCtx);
    }

    CRYPT_EAL_CipherCtx *ctx = NULL;
    switch (algorithm) {
        case 10501: // SM4_ECB
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_ECB);
            break;
        case 10502: // SM4_CBC
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_CBC);
            break;
        case 10503: // SM4_CTR
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_CTR);
            break;
        case 10504: // SM4_GCM
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_GCM);
            break;
        case 10505: // SM4_CFB
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_CFB);
            break;
        case 10506: // SM4_OFB
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_OFB);
            break;
        case 10507: // SM4_XTS
            ctx = CRYPT_EAL_CipherNewCtx(BSL_CID_SM4_XTS);
            break;
        default:
            throwException(env, "Invalid algorithm");
            return;
    }

    if (ctx == NULL) {
        throwException(env, "Failed to create cipher context");
        return;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, "Failed to get key bytes");
        return;
    }

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            CRYPT_EAL_CipherFreeCtx(ctx);
            throwException(env, "Failed to get IV bytes");
            return;
        }
        ivLen = (*env)->GetArrayLength(env, iv);
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);

    int result = CRYPT_EAL_CipherInit(ctx,
                                (const uint8_t *)keyBytes,
                                (uint32_t)keyLen,
                                ivBytes != NULL ? (const uint8_t *)ivBytes : NULL,
                                (uint32_t)ivLen,
                                mode == 1);

    if (result != CRYPT_SUCCESS) {
        if (ivBytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        }
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, "Failed to initialize cipher");
        return;
    }

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    }

    (*env)->SetLongField(env, obj, fid, (jlong)ctx);
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_getContextPtr
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return 0;
    }
    return (*env)->GetLongField(env, obj, fid);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeSetPadding
  (JNIEnv *env, jobject obj, jint paddingType) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return;
    }

    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (ctx == NULL) {
        throwException(env, "SM4 context is null");
        return;
    }

    int result = CRYPT_EAL_CipherSetPadding(ctx, paddingType);
    if (result != CRYPT_SUCCESS) {
        char errMsg[256];
        snprintf(errMsg, sizeof(errMsg), "Failed to set padding (error code: %d)", result);
        throwException(env, errMsg);
        return;
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)contextPtr;
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeEncryptUpdate
  (JNIEnv *env, jobject obj, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jintArray outLen) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return;
    }

    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (ctx == NULL) {
        throwException(env, "SM4 context is null");
        return;
    }

    jbyte *inputBytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (inputBytes == NULL) {
        throwException(env, "Failed to get input bytes");
        return;
    }

    jbyte *outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outputBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        throwException(env, "Failed to get output bytes");
        return;
    }

    jint *outLenPtr = (*env)->GetIntArrayElements(env, outLen, NULL);
    if (outLenPtr == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        throwException(env, "Failed to get outLen array");
        return;
    }

    uint32_t actualOutLen = inputLen + 16; // Allow for padding
    int result = CRYPT_EAL_CipherUpdate(ctx,
                                       (uint8_t *)(inputBytes + inputOffset),
                                       inputLen,
                                       (uint8_t *)(outputBytes + outputOffset),
                                       &actualOutLen);

    *outLenPtr = actualOutLen;
    (*env)->ReleaseIntArrayElements(env, outLen, outLenPtr, 0);
    (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

    if (result != CRYPT_SUCCESS) {
        throwException(env, "Failed to encrypt data");
        return;
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeDecryptUpdate
  (JNIEnv *env, jobject obj, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jintArray outLen) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return;
    }

    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (ctx == NULL) {
        throwException(env, "SM4 context is null");
        return;
    }

    jbyte *inputBytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (inputBytes == NULL) {
        throwException(env, "Failed to get input bytes");
        return;
    }

    jbyte *outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outputBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        throwException(env, "Failed to get output bytes");
        return;
    }

    jint *outLenPtr = (*env)->GetIntArrayElements(env, outLen, NULL);
    if (outLenPtr == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        throwException(env, "Failed to get outLen array");
        return;
    }

    uint32_t actualOutLen = inputLen;  // Start with input length

    int result = CRYPT_EAL_CipherUpdate(ctx,
                                       (uint8_t *)(inputBytes + inputOffset),
                                       inputLen,
                                       (uint8_t *)(outputBytes + outputOffset),
                                       &actualOutLen);

    *outLenPtr = actualOutLen;

    (*env)->ReleaseIntArrayElements(env, outLen, outLenPtr, 0);
    (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

    if (result != CRYPT_SUCCESS) {
        throwException(env, "Failed to decrypt data");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeEncryptFinal
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return NULL;
    }

    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (ctx == NULL) {
        throwException(env, "SM4 context is null");
        return NULL;
    }

    uint32_t outLen = 32; // Allow for up to 2 blocks of padding
    uint8_t *outBuf = malloc(outLen);
    if (outBuf == NULL) {
        throwException(env, "Failed to allocate memory for final block");
        return NULL;
    }

    int result = CRYPT_EAL_CipherFinal(ctx, outBuf, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(outBuf);
        throwException(env, "Failed to finalize encryption");
        return NULL;
    }

    jbyteArray finalBlock = NULL;
    if (outLen > 0) {
        finalBlock = (*env)->NewByteArray(env, outLen);
        if (finalBlock == NULL) {
            free(outBuf);
            throwException(env, "Failed to create final block array");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, finalBlock, 0, outLen, (jbyte *)outBuf);
    }
    free(outBuf);
    return finalBlock;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeDecryptFinal
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return NULL;
    }

    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (ctx == NULL) {
        throwException(env, "SM4 context is null");
        return NULL;
    }

    uint32_t actualOutLen = 16; // Start with one block size
    uint8_t *outBuf = malloc(actualOutLen);
    if (outBuf == NULL) {
        throwException(env, "Failed to allocate memory for final block");
        return NULL;
    }

    int result = CRYPT_EAL_CipherFinal(ctx, outBuf, &actualOutLen);

    if (result != CRYPT_SUCCESS) {
        free(outBuf);
        throwException(env, "Failed to finalize decryption");
        return NULL;
    }

    jbyteArray finalBlock = NULL;
    if (actualOutLen > 0) {
        finalBlock = (*env)->NewByteArray(env, actualOutLen);
        if (finalBlock == NULL) {
            free(outBuf);
            throwException(env, "Failed to create final block array");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, finalBlock, 0, actualOutLen, (jbyte *)outBuf);
    }
    free(outBuf);
    return finalBlock;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeReinit
  (JNIEnv *env, jobject obj) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, "contextPtr", "J");
    if (fid == NULL) {
        throwException(env, "Failed to get contextPtr field");
        return;
    }

    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)(*env)->GetLongField(env, obj, fid);
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        (*env)->SetLongField(env, obj, fid, 0L);
    }
}

JNIEXPORT jint JNICALL Java_org_openhitls_crypto_core_symmetric_SM4_nativeGetBlockSize
  (JNIEnv *env, jobject obj) {
    return 16; // SM4 block size is always 16 bytes
}