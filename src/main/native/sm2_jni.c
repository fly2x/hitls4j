#include <jni.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <include/crypt_errno.h>
#include <include/crypt_algid.h>
#include <include/crypt_eal_pkey.h>
#include <include/bsl_sal.h>
#include <include/bsl_err.h>
#include <include/crypt_eal_rand.h>
#include <pthread.h>
#include "org_openhitls_crypto_core_asymmetric_SM2.h"

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

static void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastError();  
}

static void throwException(JNIEnv *env, const char *message, int32_t errorCode) {
    char fullMessage[256];
    snprintf(fullMessage, sizeof(fullMessage), "%s (Error code: 0x%x)", message, errorCode);
    jclass exceptionClass = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (exceptionClass != NULL) {
        (*env)->ThrowNew(env, exceptionClass, fullMessage);
    }
}

static void bslInit() {
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);
}

static void randInit() {
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
}

static void initBSL() {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, bslInit);
}

static void initRand(JNIEnv *env) {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, randInit);
    
    uint8_t testBuf[32];
    int ret = CRYPT_EAL_Randbytes(testBuf, sizeof(testBuf));
    if (ret != CRYPT_SUCCESS) {
        throwException(env, "Failed to generate random number", ret);
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_createNativeContext
  (JNIEnv *env, jclass cls) {
    initBSL();
    initRand(env);

    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (pkey == NULL) {
        PrintLastError();
        throwException(env, "Failed to create SM2 context", 0);
        return 0;
    }

    return (jlong)pkey;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_freeNativeRef
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_setNativeKeys
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_SM2;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pubKey.key.eccPub.data = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        pubKey.key.eccPub.len = pubKeyLen;

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pubKey.key.eccPub.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwException(env, "Failed to set public key", ret);
            return;
        }
    }

    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_SM2;
        jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
        privKey.key.eccPrv.data = (uint8_t *)(*env)->GetByteArrayElements(env, privateKey, NULL);
        privKey.key.eccPrv.len = privKeyLen;

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
        (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privKey.key.eccPrv.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwException(env, "Failed to set private key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_setNativeUserId
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray userId) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (userId != NULL) {
        jsize userIdLen = (*env)->GetArrayLength(env, userId);
        const unsigned char *userIdData = (unsigned char *)(*env)->GetByteArrayElements(env, userId, NULL);
        
        if (userIdData != NULL) {
            ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, userIdData, userIdLen);
            (*env)->ReleaseByteArrayElements(env, userId, (jbyte *)userIdData, JNI_ABORT);
            
            if (ret != CRYPT_SUCCESS) {
                PrintLastError();
                throwException(env, "Failed to set SM2 user ID", ret);
                return;
            }
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_generateKeyPair
  (JNIEnv *env, jobject obj, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        throwException(env, "Failed to generate key pair", ret);
        return;
    }

    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_SM2;

    pubKey.key.eccPub.data = malloc(128);
    pubKey.key.eccPub.len = 128;
    if (pubKey.key.eccPub.data == NULL) {
        throwException(env, "Failed to allocate memory for public key", 0);
        return;
    }

    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        free(pubKey.key.eccPub.data);
        throwException(env, "Failed to get public key", ret);
        return;
    }

    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_SM2;

    privKey.key.eccPrv.data = malloc(32);
    privKey.key.eccPrv.len = 32;
    if (privKey.key.eccPrv.data == NULL) {
        free(pubKey.key.eccPub.data);
        throwException(env, "Failed to allocate memory for private key", 0);
        return;
    }

    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, "Failed to get private key", ret);
        return;
    }

    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fidPublicKey = (*env)->GetFieldID(env, cls, "publicKey", "[B");
    jfieldID fidPrivateKey = (*env)->GetFieldID(env, cls, "privateKey", "[B");
    if (fidPublicKey == NULL || fidPrivateKey == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, "Failed to get field IDs", 0);
        return;
    }

    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.eccPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.eccPrv.len);
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, "Failed to create byte arrays", 0);
        return;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.eccPub.len, (jbyte *)pubKey.key.eccPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.eccPrv.len, (jbyte *)privKey.key.eccPrv.data);

    (*env)->SetObjectField(env, obj, fidPublicKey, pubKeyArray);
    (*env)->SetObjectField(env, obj, fidPrivateKey, privKeyArray);

    free(pubKey.key.eccPub.data);
    free(privKey.key.eccPrv.data);
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_encrypt
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, "Failed to get input data", 0);
        return NULL;
    }

    uint8_t *outBuf = malloc(inputLen + 256);
    uint32_t outLen = inputLen + 256;
    if (outBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, "Failed to allocate memory for output buffer", 0);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyEncrypt(pkey, (uint8_t *)inputData, inputLen, outBuf, &outLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        free(outBuf);
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, "Failed to encrypt data", ret);
        return NULL;
    }

    result = (*env)->NewByteArray(env, outLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, outLen, (jbyte *)outBuf);
    }

    free(outBuf);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_decrypt
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray encryptedData) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, encryptedData, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, encryptedData);
    if (inputData == NULL) {
        throwException(env, "Failed to get input data", 0);
        return NULL;
    }

    uint8_t *decryptedData = malloc(inputLen);
    uint32_t decryptedLen = inputLen;
    if (decryptedData == NULL) {
        (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);
        throwException(env, "Failed to allocate memory for decrypted data", 0);
        return NULL;
    }

    ret = CRYPT_EAL_PkeyDecrypt(pkey, (uint8_t *)inputData, inputLen, decryptedData, &decryptedLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        free(decryptedData);
        (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);
        throwException(env, "Failed to decrypt data", ret);
        return NULL;
    }

    result = (*env)->NewByteArray(env, decryptedLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, decryptedLen, (jbyte *)decryptedData);
    }

    free(decryptedData);
    (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_sign
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, "Failed to get input data", 0);
        return NULL;
    }

    uint8_t *signBuf = malloc(256);
    uint32_t signLen = 256;
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, "Failed to allocate memory for signature", 0);
        return NULL;
    }

    ret = CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SM3, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        free(signBuf);
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, "Failed to sign data", ret);
        return NULL;
    }

    result = (*env)->NewByteArray(env, signLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signBuf);
    }

    free(signBuf);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_asymmetric_SM2_verify
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jbyteArray signature) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, "Failed to get input data", 0);
        return JNI_FALSE;
    }

    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, "Failed to get signature data", 0);
        return JNI_FALSE;
    }

    ret = CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SM3, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}