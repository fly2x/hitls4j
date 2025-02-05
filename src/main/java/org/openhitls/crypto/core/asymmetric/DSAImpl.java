package org.openhitls.crypto.core.asymmetric;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class DSAImpl extends NativeResource {
    private boolean parametersSet = false;
    private byte[] publicKey;
    private byte[] privateKey;
    private int hashAlgorithm = 4; // Default to SHA256

    public DSAImpl() {
        super(CryptoNative.dsaCreateContext(), DSAImpl::freeNativeContext);
    }

    public DSAImpl(byte[] publicKey, byte[] privateKey) {
        super(CryptoNative.dsaCreateContext(), DSAImpl::freeNativeContext);
        setKeys(publicKey, privateKey);
    }

    private static void freeNativeContext(long nativeContext) {
        if (nativeContext != 0) {
            CryptoNative.dsaFreeContext(nativeContext);
        }
    }

    public void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey != null ? publicKey.clone() : null;
        this.privateKey = privateKey != null ? privateKey.clone() : null;
        CryptoNative.dsaSetKeys(nativeContext, publicKey, privateKey);
    }

    public void setParameters(byte[] p, byte[] q, byte[] g) {
        if (p == null || q == null || g == null) {
            throw new IllegalArgumentException("DSA parameters cannot be null");
        }

        // Set parameters in native context
        CryptoNative.dsaSetParameters(nativeContext, p, q, g);
        parametersSet = true;
    }

    public void generateKeyPair() {
        if (!parametersSet) {
            throw new IllegalStateException("DSA parameters must be set before generating key pair");
        }
        
        // Generate key pair
        byte[][] keyPair = CryptoNative.dsaGenerateKeyPair(nativeContext);
        if (keyPair == null || keyPair.length != 2) {
            throw new IllegalStateException("Failed to generate DSA key pair");
        }

        publicKey = keyPair[0];
        privateKey = keyPair[1];

        if (publicKey == null || privateKey == null) {
            throw new IllegalStateException("Generated DSA key pair is invalid");
        }
    }

    public byte[] getPublicKey() {
        return publicKey != null ? publicKey.clone() : null;
    }

    public byte[] getPrivateKey() {
        return privateKey != null ? privateKey.clone() : null;
    }

    public void setHashAlgorithm(int hashAlg) {
        this.hashAlgorithm = hashAlg;
    }

    public byte[] sign(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data to sign cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }
        return CryptoNative.dsaSign(nativeContext, data, hashAlgorithm);
    }

    public boolean verify(byte[] data, byte[] signature) {
        if (data == null || signature == null) {
            throw new IllegalArgumentException("Data and signature cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalStateException("Public key not initialized");
        }
        return CryptoNative.dsaVerify(nativeContext, data, signature, hashAlgorithm);
    }
} 