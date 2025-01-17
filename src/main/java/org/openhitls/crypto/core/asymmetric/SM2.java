package org.openhitls.crypto.core.asymmetric;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import org.openhitls.crypto.NativeLoader;

public class SM2 {
    private byte[] publicKey;
    private byte[] privateKey;

    public SM2() {
        generateKeyPair();
    }

    public SM2(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    private native void generateKeyPair();
    private native byte[] encrypt(byte[] data);
    private native byte[] decrypt(byte[] encryptedData);
    private native byte[] sign(byte[] data);
    private native boolean verify(byte[] data, byte[] signature);

    void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey != null ? publicKey.clone() : null;
    }

    public byte[] getPrivateKey() {
        return privateKey != null ? privateKey.clone() : null;
    }

    /**
     * Encrypts data using SM2 public key encryption
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
        return encrypt(data);
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
        return decrypt(encryptedData);
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
        return sign(data);
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
        return verify(data, signature);
    }
} 
