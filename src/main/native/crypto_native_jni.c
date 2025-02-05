#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <include/crypt_errno.h>
#include <include/crypt_algid.h>
#include "include/crypt_eal_provider.h"
#include <include/crypt_eal_pkey.h>
#include "include/crypt_eal_cipher.h"
#include <include/crypt_eal_mac.h>
#include <include/bsl_sal.h>
#include <include/bsl_err.h>
#include <include/crypt_eal_rand.h>
#include <pthread.h>

#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "org_openhitls_crypto_core_CryptoNative.h"

// Exception type constants
static const char* INVALID_KEY_EXCEPTION = "java/security/InvalidKeyException";
static const char* INVALID_ALGORITHM_PARAMETER_EXCEPTION = "java/security/InvalidAlgorithmParameterException";
static const char* NO_SUCH_ALGORITHM_EXCEPTION = "java/security/NoSuchAlgorithmException";
static const char* ILLEGAL_STATE_EXCEPTION = "java/lang/IllegalStateException";
static const char* ILLEGAL_ARGUMENT_EXCEPTION = "java/lang/IllegalArgumentException";
static const char* SIGNATURE_EXCEPTION = "java/security/SignatureException";

static void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

static void throwException(JNIEnv *env, const char *exceptionClass, const char *message) {
    jclass cls = (*env)->FindClass(env, exceptionClass);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, message);
    }
    (*env)->DeleteLocalRef(env, cls);
}

static void throwExceptionWithError(JNIEnv *env, const char *exceptionClass, const char *message, int32_t errorCode) {
    char errorMsg[256];
    snprintf(errorMsg, sizeof(errorMsg), "%s (Error code: %d)", message, errorCode);
    jclass cls = (*env)->FindClass(env, exceptionClass);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, errorMsg);
    }
    (*env)->DeleteLocalRef(env, cls);
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

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestInit
  (JNIEnv *env, jclass cls, jstring jalgorithm) {
    initBSL();

    const char *algorithm = (*env)->GetStringUTFChars(env, jalgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Failed to get algorithm string");
        return 0;
    }

    int mdId;
    if (strcasecmp(algorithm, "SHA-1") == 0) {
        mdId = CRYPT_MD_SHA1;
    } else if (strcasecmp(algorithm, "SHA-224") == 0) {
        mdId = CRYPT_MD_SHA224;
    } else if (strcasecmp(algorithm, "SHA-256") == 0) {
        mdId = CRYPT_MD_SHA256;
    } else if (strcasecmp(algorithm, "SHA-384") == 0) {
        mdId = CRYPT_MD_SHA384;
    } else if (strcasecmp(algorithm, "SHA-512") == 0) {
        mdId = CRYPT_MD_SHA512;
    } else if (strcasecmp(algorithm, "SHA3-224") == 0) {
        mdId = CRYPT_MD_SHA3_224;
    } else if (strcasecmp(algorithm, "SHA3-256") == 0) {
        mdId = CRYPT_MD_SHA3_256;
    } else if (strcasecmp(algorithm, "SHA3-384") == 0) {
        mdId = CRYPT_MD_SHA3_384;
    } else if (strcasecmp(algorithm, "SHA3-512") == 0) {
        mdId = CRYPT_MD_SHA3_512;
    } else if (strcasecmp(algorithm, "SM3") == 0) {
        mdId = CRYPT_MD_SM3;
    } else {
        (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported hash algorithm");
        return 0;
    }
    (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(mdId);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create message digest context");
        return 0;
    }

    int ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(ctx);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to initialize message digest", ret);
        return 0;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestUpdate
  (JNIEnv *env, jobject obj, jlong contextPtr, jbyteArray data, jint offset, jint length) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid context");
        return;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get byte array elements");
        return;
    }

    int result = CRYPT_EAL_MdUpdate(ctx, (unsigned char *)(bytes + offset), length);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    
    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to update message digest");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestFinal
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid context");
        return NULL;
    }
    
    CRYPT_MD_AlgId algoId = CRYPT_EAL_MdGetId(ctx);
    uint32_t digestLen = CRYPT_EAL_MdGetDigestSize(algoId);
    unsigned char hash[128];  // Large enough for any hash
    uint32_t outLen = digestLen;
    
    if (CRYPT_EAL_MdFinal(ctx, hash, &outLen) != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to finalize message digest");
        return NULL;
    }
    
    jbyteArray result = (*env)->NewByteArray(env, digestLen);
    if (result == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }
    
    (*env)->SetByteArrayRegion(env, result, 0, digestLen, (jbyte *)hash);
    return result;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_messageDigestFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MdCTX *ctx = (CRYPT_EAL_MdCTX *)contextPtr;
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

// Get algorithm ID from algorithm name
static int getHmacAlgorithmId(const char *algorithm) {
    if (strcmp(algorithm, "HMACSHA1") == 0) {
        return CRYPT_MAC_HMAC_SHA1;
    } else if (strcmp(algorithm, "HMACSHA224") == 0) {
        return CRYPT_MAC_HMAC_SHA224;
    } else if (strcmp(algorithm, "HMACSHA256") == 0) {
        return CRYPT_MAC_HMAC_SHA256;
    } else if (strcmp(algorithm, "HMACSHA384") == 0) {
        return CRYPT_MAC_HMAC_SHA384;
    } else if (strcmp(algorithm, "HMACSHA512") == 0) {
        return CRYPT_MAC_HMAC_SHA512;
    } else if (strcmp(algorithm, "HMACSHA3-224") == 0) {
        return CRYPT_MAC_HMAC_SHA3_224;
    } else if (strcmp(algorithm, "HMACSHA3-256") == 0) {
        return CRYPT_MAC_HMAC_SHA3_256;
    } else if (strcmp(algorithm, "HMACSHA3-384") == 0) {
        return CRYPT_MAC_HMAC_SHA3_384;
    } else if (strcmp(algorithm, "HMACSHA3-512") == 0) {
        return CRYPT_MAC_HMAC_SHA3_512;
    } else if (strcmp(algorithm, "HMACSM3") == 0) {
        return CRYPT_MAC_HMAC_SM3;
    }
    return -1;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacInit
  (JNIEnv *env, jobject obj, jstring jalgorithm, jbyteArray key) {
    initBSL();

    // Convert Java string to C string
    const char *algorithm = (*env)->GetStringUTFChars(env, jalgorithm, NULL);
    if (algorithm == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get algorithm string");
        return 0;
    }

    // Get algorithm ID
    int algorithmId = getHmacAlgorithmId(algorithm);
    (*env)->ReleaseStringUTFChars(env, jalgorithm, algorithm);

    if (algorithmId == -1) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Unsupported HMAC algorithm");
        return 0;
    }

    // Verify algorithm is supported
    if (!CRYPT_EAL_MacIsValidAlgId(algorithmId)) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid HMAC algorithm");
        return 0;
    }
    
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algorithmId);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create HMAC context");
        return 0;
    }

    jbyte *keyBytes = NULL;
    jsize keyLen = 0;
    
    if (key != NULL) {
        keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
        if (keyBytes == NULL) {
            CRYPT_EAL_MacFreeCtx(ctx);
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get key bytes");
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
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to initialize HMAC");
        return 0;
    }

    if (keyBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    }
    
    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacUpdate
  (JNIEnv *env, jobject obj, jlong contextPtr, jbyteArray data, jint offset, jint length) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get data bytes");
        return;
    }

    int result = CRYPT_EAL_MacUpdate(ctx, (uint8_t *)dataBytes + offset, length);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to update HMAC");
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacFinal
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return NULL;
    }

    uint32_t macLength = CRYPT_EAL_GetMacLen(ctx);
    if (macLength == 0) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get MAC length");
        return NULL;
    }

    uint8_t *mac = malloc(macLength);
    if (mac == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for MAC");
        return NULL;
    }

    uint32_t outLen = macLength;
    int result = CRYPT_EAL_MacFinal(ctx, mac, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(mac);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to finalize HMAC");
        return NULL;
    }

    jbyteArray macArray = (*env)->NewByteArray(env, outLen);
    if (macArray == NULL) {
        free(mac);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create Java byte array");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, macArray, 0, outLen, (jbyte *)mac);
    free(mac);

    return macArray;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacReinit
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return;
    }

    int result = CRYPT_EAL_MacReinit(ctx);
    if (result != CRYPT_SUCCESS) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to reinitialize HMAC");
    }
}

JNIEXPORT jint JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacGetMacLength
  (JNIEnv *env, jobject obj, jlong contextPtr) {
    CRYPT_EAL_MacCtx *ctx = (CRYPT_EAL_MacCtx *)contextPtr;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "HMAC context is null");
        return 0;
    }

    return CRYPT_EAL_GetMacLen(ctx);
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_hmacFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_MacFreeCtx((CRYPT_EAL_MacCtx *)contextPtr);
    }
}

static void ecdsaRandInit() {
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
}

static void ecdsaInitRand(JNIEnv *env) {
    static uint32_t onceControl = 0;
    BSL_SAL_ThreadRunOnce(&onceControl, ecdsaRandInit);
    
    uint8_t testBuf[32];
    int ret = CRYPT_EAL_Randbytes(testBuf, sizeof(testBuf));
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate random number", ret);
    }
}

// Update curve IDs to match OpenHiTLS
static int getEcCurveId(const char *curveName) {
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

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaCreateContext
  (JNIEnv *env, jclass cls, jstring jcurveName) {
    initBSL();
    ecdsaInitRand(env);

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int curveId = getEcCurveId(curveName);
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    if (curveId == -1) {
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported curve");
        return 0;
    }

    // Create context based on curve type
    CRYPT_EAL_PkeyCtx *pkey;
    int ret;
    if (curveId == CRYPT_ECC_SM2) {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
        if (pkey == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create context");
            return 0;
        }
        
        // No need to set curve parameters for SM2 as it's fixed to sm2p256v1
        
        // Set the default user ID for SM2
        const char *defaultUserId = "1234567812345678";
        ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)defaultUserId, strlen(defaultUserId));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set default user ID", ret);
            return 0;
        }
    } else {
        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
        if (pkey == NULL) {
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create context");
            return 0;
        }
        
        // For ECDSA, we need to set the curve ID
        ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set curve parameters", ret);
            return 0;
        }
    }
    return (jlong)pkey;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaSetKeys
  (JNIEnv *env, jobject obj, jlong nativeRef, jstring jcurveName, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

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
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set public key", ret);
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
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set private key", ret);
            return;
        }
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaSetUserId
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
                throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set SM2 user ID", ret);
                return;
            }
        }
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef, jstring jcurveName) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    const char *curveName = (*env)->GetStringUTFChars(env, jcurveName, NULL);
    int curveId = getEcCurveId(curveName);
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
            throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Unsupported curve");
            return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, jcurveName, curveName);

    // Generate key pair
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate key pair", ret);
        return NULL;
    }

    // Get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = keyType;
    pubKey.key.eccPub.data = malloc(pubKeySize);
    pubKey.key.eccPub.len = pubKeySize;
    if (pubKey.key.eccPub.data == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for public key");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get public key", ret);
        return NULL;
    }

    // Get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = keyType;
    privKey.key.eccPrv.data = malloc(privKeySize);
    privKey.key.eccPrv.len = privKeySize;
    if (privKey.key.eccPrv.data == NULL) {
        free(pubKey.key.eccPub.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for private key");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyGetPrv(pkey, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.eccPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.eccPrv.len);
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.eccPub.len, (jbyte *)pubKey.key.eccPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.eccPrv.len, (jbyte *)privKey.key.eccPrv.data);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.eccPub.data);
        free(privKey.key.eccPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.eccPub.data);
    free(privKey.key.eccPrv.data);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaEncrypt
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint8_t *outBuf = malloc(inputLen + 256);
    uint32_t outLen = inputLen + 256;
    if (outBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for output buffer");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyEncrypt(pkey, (uint8_t *)inputData, inputLen, outBuf, &outLen);
    if (ret != CRYPT_SUCCESS) {
        free(outBuf);
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to encrypt data", ret);
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

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaDecrypt
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray encryptedData) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, encryptedData, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, encryptedData);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint8_t *decryptedData = malloc(inputLen);
    uint32_t decryptedLen = inputLen;
    if (decryptedData == NULL) {
        (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for decrypted data");
        return NULL;
    }

    ret = CRYPT_EAL_PkeyDecrypt(pkey, (uint8_t *)inputData, inputLen, decryptedData, &decryptedLen);
    if (ret != CRYPT_SUCCESS) {
        free(decryptedData);
        (*env)->ReleaseByteArrayElements(env, encryptedData, inputData, JNI_ABORT);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to decrypt data", ret);
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

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaSign
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;
    jbyteArray result = NULL;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    uint8_t *signBuf = malloc(256);
    uint32_t signLen = 256;
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeySign(pkey, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
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

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_ecdsaVerify
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)nativeRef;
    int ret;

    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }

    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get signature data");
        return JNI_FALSE;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static CRYPT_CIPHER_AlgId getSM4ModeId(JNIEnv *env, jstring mode) {
    CRYPT_CIPHER_AlgId algId = (CRYPT_CIPHER_AlgId)0;
    const char* modeStr = (*env)->GetStringUTFChars(env, mode, NULL);
    if (modeStr == NULL) {
        return algId;
    }
    if (strcmp(modeStr, "ECB") == 0) {
        algId = BSL_CID_SM4_ECB;
    } else if (strcmp(modeStr, "CBC") == 0) {
        algId = BSL_CID_SM4_CBC;           
    } else if (strcmp(modeStr, "CTR") == 0) {
        algId = BSL_CID_SM4_CTR; 
    } else if (strcmp(modeStr, "GCM") == 0) {
        algId = BSL_CID_SM4_GCM;
    } else if (strcmp(modeStr, "CFB") == 0) {
        algId = BSL_CID_SM4_CFB;
    } else if (strcmp(modeStr, "OFB") == 0) {
        algId = BSL_CID_SM4_OFB;
    } else if (strcmp(modeStr, "XTS") == 0) {
        algId = BSL_CID_SM4_XTS;
    }

    (*env)->ReleaseStringUTFChars(env, mode, modeStr);
    return algId;
}

static CRYPT_CIPHER_AlgId getAesModeId(JNIEnv *env, jstring mode, jint keySize) {
    CRYPT_CIPHER_AlgId algId = (CRYPT_CIPHER_AlgId)0;
    const char* modeStr = (*env)->GetStringUTFChars(env, mode, NULL);
    if (modeStr == NULL) {
        return algId;
    }

    if (strcmp(modeStr, "ECB") == 0) {
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
    } else if (strcmp(modeStr, "CBC") == 0) {
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
    } else if (strcmp(modeStr, "CTR") == 0) {
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
    } else if (strcmp(modeStr, "GCM") == 0) {
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
    } else if (strcmp(modeStr, "CFB") == 0) {
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
    } else if (strcmp(modeStr, "OFB") == 0) {
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
    }

    (*env)->ReleaseStringUTFChars(env, mode, modeStr);
    return algId;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherInit
  (JNIEnv *env, jclass cls, jstring algorithm, jstring cipherMode, jbyteArray key, jbyteArray iv, jint mode) {
    initBSL();

    CRYPT_CIPHER_AlgId algId = 0;
    const char* algoStr = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (strcmp(algoStr, "AES") == 0) {
        // Get key size in bits
        jsize keyLen = (*env)->GetArrayLength(env, key);
        jint keySize = keyLen * 8;  // Convert bytes to bits
        algId = getAesModeId(env, cipherMode, keySize);
        if (algId == (CRYPT_CIPHER_AlgId)0) {
            (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
            throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "Invalid AES mode or key size");
            return 0;
        }
    } else if (strcmp(algoStr, "SM4") == 0) {
        algId = getSM4ModeId(env, cipherMode);
        if (algId == (CRYPT_CIPHER_AlgId)0) {
            (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
            throwException(env, INVALID_ALGORITHM_PARAMETER_EXCEPTION, "Invalid SM4 mode.");
            return 0;
        }
    } else {
        (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);
        throwException(env, NO_SUCH_ALGORITHM_EXCEPTION, "Invalid algorithm");
        return 0;
    }
    (*env)->ReleaseStringUTFChars(env, algorithm, algoStr);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create cipher context");
        return 0;
    }
    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get key bytes");
        return 0;
    }

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            CRYPT_EAL_CipherFreeCtx(ctx);
            throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get IV bytes");
            return 0;
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
        throwException(env, INVALID_KEY_EXCEPTION, "Failed to initialize cipher");
        return 0;
    }

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherSetPadding
  (JNIEnv *env, jobject obj, jlong nativeRef, jint paddingType) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Symmetric cipher context is null");
        return;
    }

    int result = CRYPT_EAL_CipherSetPadding(ctx, paddingType);
    if (result != CRYPT_SUCCESS) {
        char errMsg[256];
        snprintf(errMsg, sizeof(errMsg), "Failed to set padding (error code: %d)", result);
        throwException(env, ILLEGAL_STATE_EXCEPTION, errMsg);
        return;
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherFree
  (JNIEnv *env, jclass cls, jlong contextPtr) {
    if (contextPtr != 0) {
        CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)contextPtr;
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherUpdate
  (JNIEnv *env, jobject obj, jlong nativeRef, jbyteArray input, jint inputOffset, jint inputLen,
   jbyteArray output, jint outputOffset, jintArray outLen) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Symmetric cipher context is null");
        return;
    }

    jbyte *inputBytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (inputBytes == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input bytes");
        return;
    }

    jbyte *outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
    if (outputBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get output bytes");
        return;
    }

    jint *outLenPtr = (*env)->GetIntArrayElements(env, outLen, NULL);
    if (outLenPtr == NULL) {
        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get outLen array");
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
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to encrypt data");
        return;
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_symmetricCipherFinal
  (JNIEnv *env, jobject obj, jlong nativeRef) {
    CRYPT_EAL_CipherCtx *ctx = (CRYPT_EAL_CipherCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Symmetric cipher context is null");
        return NULL;
    }

    uint32_t outLen = 32; // Allow for up to 2 blocks of padding
    uint8_t *outBuf = malloc(outLen);
    if (outBuf == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for final block");
        return NULL;
    }

    int result = CRYPT_EAL_CipherFinal(ctx, outBuf, &outLen);
    if (result != CRYPT_SUCCESS) {
        free(outBuf);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to finalize encryption");
        return NULL;
    }

    jbyteArray finalBlock = NULL;
    if (outLen > 0) {
        finalBlock = (*env)->NewByteArray(env, outLen);
        if (finalBlock == NULL) {
            free(outBuf);
            throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create final block array");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, finalBlock, 0, outLen, (jbyte *)outBuf);
    }
    free(outBuf);
    return finalBlock;
}

JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaCreateContext
  (JNIEnv *env, jclass cls) {
    initBSL();
    ecdsaInitRand(env);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DSA);
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create DSA context");
        return 0;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaFreeContext
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    if (nativeRef != 0) {
        CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaSetParameters
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray p, jbyteArray q, jbyteArray g) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return;
    }

    // Get parameter bytes
    jbyte *pBytes = (*env)->GetByteArrayElements(env, p, NULL);
    jbyte *qBytes = (*env)->GetByteArrayElements(env, q, NULL);
    jbyte *gBytes = (*env)->GetByteArrayElements(env, g, NULL);
    
    if (pBytes == NULL || qBytes == NULL || gBytes == NULL) {
        if (pBytes) (*env)->ReleaseByteArrayElements(env, p, pBytes, JNI_ABORT);
        if (qBytes) (*env)->ReleaseByteArrayElements(env, q, qBytes, JNI_ABORT);
        if (gBytes) (*env)->ReleaseByteArrayElements(env, g, gBytes, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get parameter bytes");
        return;
    }

    jsize pLen = (*env)->GetArrayLength(env, p);
    jsize qLen = (*env)->GetArrayLength(env, q);
    jsize gLen = (*env)->GetArrayLength(env, g);

    // Set up DSA parameters
    CRYPT_EAL_PkeyPara para;
    memset(&para, 0, sizeof(CRYPT_EAL_PkeyPara));
    para.id = CRYPT_PKEY_DSA;
    para.para.dsaPara.p = (uint8_t *)pBytes;
    para.para.dsaPara.pLen = pLen;
    para.para.dsaPara.q = (uint8_t *)qBytes;
    para.para.dsaPara.qLen = qLen;
    para.para.dsaPara.g = (uint8_t *)gBytes;
    para.para.dsaPara.gLen = gLen;

    // Set parameters in context
    int ret = CRYPT_EAL_PkeySetPara(ctx, &para);

    // Release byte arrays
    (*env)->ReleaseByteArrayElements(env, p, pBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, q, qBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, g, gBytes, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set DSA parameters", ret);
        return;
    }
}

JNIEXPORT jobjectArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaGenerateKeyPair
  (JNIEnv *env, jclass cls, jlong nativeRef) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return NULL;
    }

    // Generate key pair
    int ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to generate DSA key pair", ret);
        return NULL;
    }

    // Get public key
    CRYPT_EAL_PkeyPub pubKey;
    memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
    pubKey.id = CRYPT_PKEY_DSA;
    pubKey.key.dsaPub.data = malloc(128); // 1024 bits
    pubKey.key.dsaPub.len = 128;

    ret = CRYPT_EAL_PkeyGetPub(ctx, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.dsaPub.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get DSA public key", ret);
        return NULL;
    }

    // Get private key
    CRYPT_EAL_PkeyPrv privKey;
    memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
    privKey.id = CRYPT_PKEY_DSA;
    privKey.key.dsaPrv.data = malloc(20); // 160 bits
    privKey.key.dsaPrv.len = 20;

    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privKey);
    if (ret != CRYPT_SUCCESS) {
        free(pubKey.key.dsaPub.data);
        free(privKey.key.dsaPrv.data);
        throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to get DSA private key", ret);
        return NULL;
    }

    // Create byte arrays for public and private keys
    jbyteArray pubKeyArray = (*env)->NewByteArray(env, pubKey.key.dsaPub.len);
    jbyteArray privKeyArray = (*env)->NewByteArray(env, privKey.key.dsaPrv.len);
    
    if (pubKeyArray == NULL || privKeyArray == NULL) {
        free(pubKey.key.dsaPub.data);
        free(privKey.key.dsaPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create key arrays");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, pubKeyArray, 0, pubKey.key.dsaPub.len, (jbyte *)pubKey.key.dsaPub.data);
    (*env)->SetByteArrayRegion(env, privKeyArray, 0, privKey.key.dsaPrv.len, (jbyte *)privKey.key.dsaPrv.data);

    // Create array of byte arrays to return both keys
    jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->GetObjectClass(env, pubKeyArray), NULL);
    if (result == NULL) {
        free(pubKey.key.dsaPub.data);
        free(privKey.key.dsaPrv.data);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to create result array");
        return NULL;
    }

    (*env)->SetObjectArrayElement(env, result, 0, pubKeyArray);
    (*env)->SetObjectArrayElement(env, result, 1, privKeyArray);

    free(pubKey.key.dsaPub.data);
    free(privKey.key.dsaPrv.data);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaSign
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return NULL;
    }

    // Get input data
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return NULL;
    }

    // Allocate buffer for signature
    uint8_t *signBuf = malloc(256); // Large enough for DSA signature
    uint32_t signLen = 256;
    if (signBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Failed to allocate memory for signature");
        return NULL;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    int ret = CRYPT_EAL_PkeySign(ctx, mdId, (uint8_t *)inputData, inputLen, signBuf, &signLen);
    
    // Release input data
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);

    if (ret != CRYPT_SUCCESS) {
        free(signBuf);
        throwExceptionWithError(env, SIGNATURE_EXCEPTION, "Failed to sign data", ret);
        return NULL;
    }

    // Create result byte array
    jbyteArray result = (*env)->NewByteArray(env, signLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, signLen, (jbyte *)signBuf);
    }

    free(signBuf);
    return result;
}

JNIEXPORT jboolean JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaVerify
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray data, jbyteArray signature, jint hashAlg) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return JNI_FALSE;
    }

    // Get input data
    jbyte *inputData = (*env)->GetByteArrayElements(env, data, NULL);
    jsize inputLen = (*env)->GetArrayLength(env, data);
    if (inputData == NULL) {
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get input data");
        return JNI_FALSE;
    }

    // Get signature data
    jbyte *signData = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize signLen = (*env)->GetArrayLength(env, signature);
    if (signData == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
        throwException(env, ILLEGAL_ARGUMENT_EXCEPTION, "Failed to get signature data");
        return JNI_FALSE;
    }

    // Map Java hash algorithm to OpenHiTLS MD ID
    int mdId = getMdId(hashAlg);
    int ret = CRYPT_EAL_PkeyVerify(ctx, mdId, (uint8_t *)inputData, inputLen, (uint8_t *)signData, signLen);

    // Release arrays
    (*env)->ReleaseByteArrayElements(env, data, inputData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, signData, JNI_ABORT);

    return (ret == CRYPT_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_org_openhitls_crypto_core_CryptoNative_dsaSetKeys
  (JNIEnv *env, jclass cls, jlong nativeRef, jbyteArray publicKey, jbyteArray privateKey) {
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)nativeRef;
    if (ctx == NULL) {
        throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid DSA context");
        return;
    }

    if (publicKey != NULL) {
        CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_DSA;
        jsize pubKeyLen = (*env)->GetArrayLength(env, publicKey);
        pubKey.key.dsaPub.data = (uint8_t *)(*env)->GetByteArrayElements(env, publicKey, NULL);
        pubKey.key.dsaPub.len = pubKeyLen;

        int ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
        (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)pubKey.key.dsaPub.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set public key", ret);
            return;
        }
    }

    if (privateKey != NULL) {
        CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_DSA;
        jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
        privKey.key.dsaPrv.data = (uint8_t *)(*env)->GetByteArrayElements(env, privateKey, NULL);
        privKey.key.dsaPrv.len = privKeyLen;

        int ret = CRYPT_EAL_PkeySetPrv(ctx, &privKey);
        (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privKey.key.dsaPrv.data, JNI_ABORT);
        if (ret != CRYPT_SUCCESS) {
            throwExceptionWithError(env, ILLEGAL_STATE_EXCEPTION, "Failed to set private key", ret);
            return;
        }
    }
}