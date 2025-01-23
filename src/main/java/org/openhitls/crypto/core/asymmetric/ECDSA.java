package org.openhitls.crypto.core.asymmetric;

import java.lang.ref.Cleaner;

public class ECDSA {
    private static final Cleaner CLEANER = Cleaner.create();
    private final long nativeRef;
    private byte[] publicKey;
    private byte[] privateKey;
    private byte[] userId;
    private final String curveName;
    private final int hashAlgorithm;
    private final CleanerRunnable cleanerRunnable;

    private static class CleanerRunnable implements Runnable {
        private final long nativeRef;

        CleanerRunnable(long nativeRef) {
            this.nativeRef = nativeRef;
        }

        @Override
        public void run() {
            if (nativeRef != 0) {
                freeNativeRef(nativeRef);
            }
        }
    }

    public ECDSA(String curveName) {
        this.curveName = curveName.toLowerCase();
        this.hashAlgorithm = 0;  // Default
        this.nativeRef = createNativeContext(this.curveName);
        this.cleanerRunnable = new CleanerRunnable(nativeRef);
        CLEANER.register(this, cleanerRunnable);
        generateKeyPair(nativeRef);
    }

    public ECDSA(String curveName, int hashAlgorithm) {
        this.curveName = curveName;
        this.hashAlgorithm = hashAlgorithm;
        this.nativeRef = createNativeContext(curveName);
        this.cleanerRunnable = new CleanerRunnable(nativeRef);
        CLEANER.register(this, cleanerRunnable);
        generateKeyPair(nativeRef);
    }

    public ECDSA(String curveName, byte[] publicKey, byte[] privateKey) {
        this(curveName, 0, publicKey, privateKey);
    }

    public ECDSA(String curveName, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        this.curveName = curveName;
        this.hashAlgorithm = hashAlgorithm;
        this.nativeRef = createNativeContext(curveName);
        this.cleanerRunnable = new CleanerRunnable(nativeRef);
        CLEANER.register(this, cleanerRunnable);
        setKeys(publicKey, privateKey);
    }

    private static native long createNativeContext(String curveName);
    private static native void freeNativeRef(long nativeRef);
    private native void generateKeyPair(long nativeRef);
    private native byte[] encrypt(long nativeRef, byte[] data);
    private native byte[] decrypt(long nativeRef, byte[] encryptedData);
    private native byte[] sign(long nativeRef, byte[] data, int hashAlg);
    private native boolean verify(long nativeRef, byte[] data, byte[] signature, int hashAlg);

    void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        setNativeKeys(nativeRef, publicKey, privateKey);
    }

    private native void setNativeKeys(long nativeRef, byte[] publicKey, byte[] privateKey);

    public void setUserId(byte[] userId) {
        if (userId == null) {
            throw new IllegalArgumentException("UserId cannot be null");
        }
        this.userId = userId.clone();
        setNativeUserId(nativeRef, userId);
    }

    private native void setNativeUserId(long nativeRef, byte[] userId);

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
        return encrypt(nativeRef, data);
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
        return decrypt(nativeRef, encryptedData);
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
        return sign(nativeRef, data, hashAlgorithm);
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
        return verify(nativeRef, data, signature, hashAlgorithm);
    }

    public String getCurveName() {
        return curveName;
    }
}
