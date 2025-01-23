#include <jni.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "org_openhitls_crypto_core_symmetric_AES.h"
#include "include/crypt_errno.h"
#include "include/crypt_algid.h"
#include "include/crypt_eal_cipher.h"
#include "include/crypt_eal_provider.h"
#include "include/bsl_sal.h"
#include "include/bsl_err.h"

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

static void throwException(JNIEnv *env, const char *message) {
    jclass exceptionClass = (*env)->FindClass(env, "org/openhitls/crypto/exception/CryptoException");
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, message);
    }
    (*env)->DeleteLocalRef(env, exceptionClass);
}

static void throwExceptionWithError(JNIEnv *env, const char *message, int32_t errorCode) {
    char errorMsg[256];
    snprintf(errorMsg, sizeof(errorMsg), "%s (Error code: %d)", message, errorCode);
    jclass exceptionClass = (*env)->FindClass(env, "org/openhitls/crypto/exception/CryptoException");
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, errorMsg);
    }
    (*env)->DeleteLocalRef(env, exceptionClass);
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

static CRYPT_CIPHER_AlgId getModeId(jint mode, jint keySize) {
    CRYPT_CIPHER_AlgId algId = (CRYPT_CIPHER_AlgId)0;

    switch (mode) {
        case 1:  // ECB
            switch (keySize) {
                case 128:
                    algId = CRYPT_CIPHER_AES128_ECB;
                    break;
                case 192:
                    algId = CRYPT_CIPHER_AES192_ECB;
                    break;
                case 256:
                    algId = CRYPT_CIPHER_AES256_ECB;
                    break;
            }
            break;
        case 2:  // CBC
            switch (keySize) {
                case 128:
                    algId = CRYPT_CIPHER_AES128_CBC;
                    break;
                case 192:
                    algId = CRYPT_CIPHER_AES192_CBC;
                    break;
                case 256:
                    algId = CRYPT_CIPHER_AES256_CBC;
                    break;
            }
            break;
        case 3:  // CTR
            switch (keySize) {
                case 128:
                    algId = CRYPT_CIPHER_AES128_CTR;
                    break;
                case 192:
                    algId = CRYPT_CIPHER_AES192_CTR;
                    break;
                case 256:
                    algId = CRYPT_CIPHER_AES256_CTR;
                    break;
            }
            break;
        case 4:  // GCM
            switch (keySize) {
                case 128:
                    algId = CRYPT_CIPHER_AES128_GCM;
                    break;
                case 192:
                    algId = CRYPT_CIPHER_AES192_GCM;
                    break;
                case 256:
                    algId = CRYPT_CIPHER_AES256_GCM;
                    break;
            }
            break;
        case 5:  // CFB
            switch (keySize) {
                case 128:
                    algId = CRYPT_CIPHER_AES128_CFB;
                    break;
                case 192:
                    algId = CRYPT_CIPHER_AES192_CFB;
                    break;
                case 256:
                    algId = CRYPT_CIPHER_AES256_CFB;
                    break;
            }
            break;
        case 6:  // OFB
            switch (keySize) {
                case 128:
                    algId = CRYPT_CIPHER_AES128_OFB;
                    break;
                case 192:
                    algId = CRYPT_CIPHER_AES192_OFB;
                    break;
                case 256:
                    algId = CRYPT_CIPHER_AES256_OFB;
                    break;
            }
            break;
    }

    return algId;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_symmetric_AES_nativeInit
  (JNIEnv *env, jobject obj, jint mode, jbyteArray key, jbyteArray iv, jint opmode, jint keySize) {
    initBSL();

    // Validate key size
    if (keySize != 128 && keySize != 192 && keySize != 256) {
        throwException(env, "Invalid key size");
        return 0;
    }

    // Get algorithm ID
    CRYPT_CIPHER_AlgId algId = getModeId(mode, keySize);
    if (algId == (CRYPT_CIPHER_AlgId)0) {
        throwException(env, "Invalid AES mode or key size");
        return 0;
    }

    // Create cipher context
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    if (ctx == NULL) {
        throwException(env, "Failed to create cipher context");
        return 0;
    }

    // Get key data
    jbyte *keyData = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyData == NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, "Failed to get key data");
        return 0;
    }
    jsize keyLen = (*env)->GetArrayLength(env, key);

    // Get IV if provided
    jbyte *ivData = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivData = (*env)->GetByteArrayElements(env, iv, NULL);
        ivLen = (*env)->GetArrayLength(env, iv);
        if (ivData == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyData, JNI_ABORT);
            CRYPT_EAL_CipherFreeCtx(ctx);
            throwException(env, "Failed to get IV data");
            return 0;
        }
    } else if (mode != 1) {  // Not ECB mode
        (*env)->ReleaseByteArrayElements(env, key, keyData, JNI_ABORT);
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, "IV required for non-ECB mode");
        return 0;
    }

    // Initialize cipher
    bool isEncrypt = (opmode == 1); // MODE_ENCRYPT = 1

    int32_t ret = CRYPT_EAL_CipherInit(ctx, 
                                      (uint8_t *)keyData, 
                                      keyLen,
                                      ivData != NULL ? (uint8_t *)ivData : NULL,
                                      ivData != NULL ? ivLen : 0,
                                      isEncrypt);

    // Clean up
    (*env)->ReleaseByteArrayElements(env, key, keyData, JNI_ABORT);
    if (ivData != NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, ivData, JNI_ABORT);
    }

    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwExceptionWithError(env, "Failed to initialize cipher", ret);
        return 0;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_AES_nativeUpdate
  (JNIEnv *env, jobject obj, jlong handle, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)handle;
    if (ctx == NULL) {
        throwException(env, "Cipher context is null");
        return;
    }

    // Validate input parameters
    if (input == NULL) {
        throwException(env, "Input buffer is null");
        return;
    }

    if (output == NULL) {
        throwException(env, "Output buffer is null");
        return;
    }

    jsize inputLength = (*env)->GetArrayLength(env, input);
    jsize outputLength = (*env)->GetArrayLength(env, output);

    // Validate offsets and lengths
    if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > inputLength) {
        throwException(env, "Invalid input offset or length");
        return;
    }

    if (outputOffset < 0 || outputOffset + inputLen > outputLength) {
        throwException(env, "Invalid output offset or buffer too small");
        return;
    }

    // Get input data
    jbyte *inputData = (*env)->GetByteArrayElements(env, input, NULL);
    if (inputData == NULL) {
        throwException(env, "Failed to get input data");
        return;
    }

    // Get output buffer
    jbyte *outputData = (*env)->GetByteArrayElements(env, output, NULL);
    if (outputData == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputData, JNI_ABORT);
        throwException(env, "Failed to get output buffer");
        return;
    }

    // Process data
    uint32_t outLen = inputLen;  // Expected output length
    int32_t ret = CRYPT_EAL_CipherUpdate(ctx, 
                                        (uint8_t *)inputData + inputOffset, 
                                        inputLen,
                                        (uint8_t *)outputData + outputOffset, 
                                        &outLen);

    // Clean up
    (*env)->ReleaseByteArrayElements(env, input, inputData, JNI_ABORT);
    
    // Handle errors
    if (ret != CRYPT_SUCCESS) {
        (*env)->ReleaseByteArrayElements(env, output, outputData, JNI_ABORT);
        throwExceptionWithError(env, "Failed to update cipher", ret);
        return;
    }

    // Only commit output buffer if we have data
    if (outLen > 0) {
        (*env)->ReleaseByteArrayElements(env, output, outputData, 0);
    } else {
        (*env)->ReleaseByteArrayElements(env, output, outputData, JNI_ABORT);
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_symmetric_AES_nativeFinal
  (JNIEnv *env, jobject obj, jlong handle) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)handle;
    if (ctx == NULL) {
        throwException(env, "Cipher context is null");
        return NULL;
    }

    uint8_t buffer[32];  // Double AES block size to handle any padding
    uint32_t outLen = 0;
    int32_t ret = CRYPT_EAL_CipherFinal(ctx, buffer, &outLen);

    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, "Failed to finalize cipher", ret);
        return NULL;
    }

    if (outLen == 0) {
        return (*env)->NewByteArray(env, 0);
    }

    jbyteArray result = (*env)->NewByteArray(env, outLen);
    if (result == NULL) {
        throwException(env, "Failed to create result array");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, outLen, (jbyte *)buffer);
    return result;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_symmetric_AES_nativeFree
  (JNIEnv *env, jclass cls, jlong handle) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)handle;
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}
