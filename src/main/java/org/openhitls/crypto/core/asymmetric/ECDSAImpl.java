package org.openhitls.crypto.core.asymmetric;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class ECDSAImpl extends NativeResource {
    private byte[] publicKey;
    private byte[] privateKey;
    private byte[] userId;
    private final String curveName;
    private final int hashAlgorithm;

    public ECDSAImpl(String curveName) {
        this(curveName, 0);
    }

    public ECDSAImpl(String curveName, int hashAlgorithm) {
        super(initContext(curveName), CryptoNative::ecdsaFreeContext);
        this.curveName = curveName;
        this.hashAlgorithm = hashAlgorithm;
        byte[][] keyPair = CryptoNative.ecdsaGenerateKeyPair(nativeContext, this.curveName);
        setKeys(keyPair[0], keyPair[1]);
    }

    public ECDSAImpl(String curveName, byte[] publicKey, byte[] privateKey) {
        this(curveName, 0, publicKey, privateKey);
    }

    public ECDSAImpl(String curveName, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        super(initContext(curveName), CryptoNative::ecdsaFreeContext);
        this.curveName = curveName;
        this.hashAlgorithm = hashAlgorithm;
        setKeys(publicKey, privateKey);
    }

    private static long initContext(String curveName) {
        if (curveName == null) {
            throw new IllegalArgumentException("Curve name cannot be null");
        }
        return CryptoNative.ecdsaCreateContext(curveName);
    }

    void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        CryptoNative.ecdsaSetKeys(nativeContext, curveName, publicKey, privateKey);
    }

    public void setUserId(byte[] userId) {
        if (userId == null) {
            throw new IllegalArgumentException("UserId cannot be null");
        }
        this.userId = userId.clone();
        CryptoNative.ecdsaSetUserId(nativeContext, userId);
    }

    public byte[] getUserId() {
        return userId != null ? userId.clone() : null;
    }

    public byte[] getPublicKey() {
        return publicKey != null ? publicKey.clone() : null;
    }

    public byte[] getPrivateKey() {
        return privateKey != null ? privateKey.clone() : null;
    }

    /**
     * Encrypts data using ECDSA public key encryption
     * @param data The data to encrypt
     * @return The encrypted data
     * @throws RuntimeException if encryption fails
     */
    public byte[] encryptData(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalStateException("Public key not initialized");
        }
        return CryptoNative.ecdsaEncrypt(nativeContext, data);
    }

    /**
     * Decrypts data using SM2 private key decryption
     * @param encryptedData The data to decrypt
     * @return The decrypted data
     * @throws RuntimeException if decryption fails
     */
    public byte[] decryptData(byte[] encryptedData) {
        if (encryptedData == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }
        return CryptoNative.ecdsaDecrypt(nativeContext, encryptedData);
    }

    /**
     * Signs data using SM2 private key
     * @param data The data to sign
     * @return The signature
     * @throws RuntimeException if signing fails
     */
    public byte[] signData(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }
        return CryptoNative.ecdsaSign(nativeContext, data, hashAlgorithm);
    }

    /**
     * Verifies a signature using SM2 public key
     * @param data The original data
     * @param signature The signature to verify
     * @return true if signature is valid, false otherwise
     * @throws RuntimeException if verification fails
     */
    public boolean verifySignature(byte[] data, byte[] signature) {
        if (data == null || signature == null) {
            throw new IllegalArgumentException("Input data and signature cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalStateException("Public key not initialized");
        }
        return CryptoNative.ecdsaVerify(nativeContext, data, signature, hashAlgorithm);
    }

    public String getCurveName() {
        return curveName;
    }
}
