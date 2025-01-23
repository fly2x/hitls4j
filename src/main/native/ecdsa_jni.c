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
#include "org_openhitls_crypto_core_asymmetric_ECDSA.h"

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
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

// Update curve IDs to match OpenHiTLS
static int getCurveId(const char *curveName) {
    if (strcmp(curveName, "sm2p256v1") == 0) {
        return CRYPT_ECC_SM2;  // Use correct constant
    } else if (strcmp(curveName, "secp256r1") == 0 || 
               strcmp(curveName, "prime256v1") == 0 || 
               strcmp(curveName, "p-256") == 0) {
        return CRYPT_ECC_NISTP256;  // Use correct constant
    } else if (strcmp(curveName, "secp384r1") == 0 || 
               strcmp(curveName, "p-384") == 0) {
        return CRYPT_ECC_NISTP384;  // Use correct constant
    } else if (strcmp(curveName, "secp521r1") == 0 || 
               strcmp(curveName, "p-521") == 0) {
        return CRYPT_ECC_NISTP521;  // Use correct constant
    }
    return -1;
}

// Map Java hash algorithm constants to OpenHiTLS MD IDs
static int getMdId(int hashAlg) {
    switch (hashAlg) {
        case 1:  // HASH_ALG_SM3
            return CRYPT_MD_SM3;
        case 2:  // HASH_ALG_SHA1
            return CRYPT_MD_SHA1;
        case 3:  // HASH_ALG_SHA224
            return CRYPT_MD_SHA224;
        case 4:  // HASH_ALG_SHA256
            return CRYPT_MD_SHA256;
        case 5:  // HASH_ALG_SHA384
            return CRYPT_MD_SHA384;
        case 6:  // HASH_ALG_SHA512
            return CRYPT_MD_SHA512;
        default:
            return CRYPT_MD_SHA256; // Default to SHA256
    }
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_createNativeContext
  (JNIEnv *env, jclass cls, jstring jcurveName) {
    initBSL();
    initRand(env);

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int curveId = getCurveId(curveName);
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    if (curveId == -1) {
        throwException(env, "Unsupported curve", 0);
        return 0;
    }

    // Create context based on curve type
    CRYPT_EAL_PkeyCtx *pkey;
    int ret;
    if (curveId == CRYPT_ECC_SM2) {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
        if (pkey == NULL) {
            throwException(env, "Failed to create context", 0);
            return 0;
        }
        
        // No need to set curve parameters for SM2 as it's fixed to sm2p256v1
        
        // Set the default user ID for SM2
        const char *defaultUserId = "1234567812345678";
        ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)defaultUserId, strlen(defaultUserId));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwException(env, "Failed to set default user ID", ret);
            return 0;
        }
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
        if (pkey == NULL) {
            throwException(env, "Failed to create context", 0);
            return 0;
        }
        
        // For ECDSA, we need to set the curve ID
        ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwException(env, "Failed to set curve parameters", ret);
            return 0;
        }
    }
    return (jlong)pkey;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_freeNativeRef
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_setNativeKeys
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // Get curve name to determine key type
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fidCurveName = (*env)->GetFieldID(env, cls, "curveName", "Ljava/lang/String;");
    if (fidCurveName == NULL) {
        throwException(env, "Failed to get curveName field", 0);
        return;
    }

    jstring jcurveName = (*env)->GetObjectField(env, obj, fidCurveName);
    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int keyType = strcmp(curveName, "sm2p256v1") == 0 ? CRYPT_PKEY_SM2 : CRYPT_PKEY_ECDSA;
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = keyType;
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
        privKey.id = keyType;
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

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_setNativeUserId
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray userId) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    if (userId != NULL) {
        jsize userIdLen = (*env)->GetArrayLength(env, userId);
        const unsigned char *userIdData = (const unsigned char *)(*env)->GetByteArrayElements(env, userId, NULL);
        
        if (userIdData != NULL) {
            ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)userIdData, userIdLen);
            (*env)->ReleaseByteArrayElements(env, userId, (jbyte *)userIdData, JNI_ABORT);
            
            if (ret != CRYPT_SUCCESS) {
                throwException(env, "Failed to set SM2 user ID", ret);
                return;
            }
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_generateKeyPair
  (JNIEnv *env, jobject obj, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    // Get curve name to determine key type and size
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fidCurveName = (*env)->GetFieldID(env, cls, "curveName", "Ljava/lang/String;");
    if (fidCurveName == NULL) {
        throwException(env, "Failed to get curveName field", 0);
        return;
    }

    jstring jcurveName = (*env)->GetObjectField(env, obj, fidCurveName);
    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int curveId = getCurveId(curveName);
    int keyType = (curveId == CRYPT_ECC_SM2) ? CRYPT_PKEY_SM2 : CRYPT_PKEY_ECDSA;

    // Get key sizes based on curve
    int privKeySize;
    int pubKeySize;
    switch (curveId) {
        case CRYPT_ECC_SM2:
        case CRYPT_ECC_NISTP256:
            privKeySize = 32;  // 256 bits
            pubKeySize = 65;   // 0x04 + 32 bytes X + 32 bytes Y
            break;
        case CRYPT_ECC_NISTP384:
            privKeySize = 48;  // 384 bits
            pubKeySize = 97;   // 0x04 + 48 bytes X + 48 bytes Y
            break;
        case CRYPT_ECC_NISTP521:
            privKeySize = 66;  // 521 bits
            pubKeySize = 133;   // 0x04 + 66 bytes X + 66 bytes Y
            break;
        default:
            (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);
            throwException(env, "Unsupported curve", 0);
            return;
    }
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    // Generate key pair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwException(env, "Failed to generate key pair", ret);
        return;
    }

    // Get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = keyType;
    pubKey.key.eccPub.data = malloc(pubKeySize);
    pubKey.key.eccPub.len = pubKeySize;
    if (pubKey.key.eccPub.data == NULL) {
        throwException(env, "Failed to allocate memory for public key", 0);
        return;
    }

    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        throwException(env, "Failed to get public key", ret);
        return;
    }

    // Get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = keyType;
    privKey.key.eccPrv.data = malloc(privKeySize);
    privKey.key.eccPrv.len = privKeySize;
    if (privKey.key.eccPrv.data == NULL) {
        free(pubKey.key.eccPub.data);
        throwException(env, "Failed to allocate memory for private key", 0);
        return;
    }

    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, "Failed to get private key", ret);
        return;
    }

    // Set the keys in Java object
    jmethodID mid = (*env)->GetMethodID(env, cls, "setKeys", "([B[B)V");
    if (mid == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, "Failed to get setKeys method", 0);
        return;
    }

    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.eccPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.eccPrv.len);
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, "Failed to create key arrays", 0);
        return;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.eccPub.len, (jbyte *)pubKey.key.eccPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.eccPrv.len, (jbyte *)privKey.key.eccPrv.data);
    (*env)->CallVoidMethod(env, obj, mid, pubKeyArray, privKeyArray);

    free(pubKey.key.eccPub.data);
    free(privKey.key.eccPrv.data);
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_encrypt
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

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_decrypt
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

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_sign
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jint hashAlg) {
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

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeySign(pkey, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    if (ret != CRYPT_SUCCESS) {
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

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_asymmetric_ECDSA_verify
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
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

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}