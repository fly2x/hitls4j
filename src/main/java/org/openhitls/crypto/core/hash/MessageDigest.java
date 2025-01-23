package org.openhitls.crypto.core.hash;

import java.lang.ref.Cleaner;

public class MessageDigest {
    private static final Cleaner CLEANER = Cleaner.create();
    private final long contextPtr;
    private final CleanerRunnable cleanerRunnable;
    private final String algorithm;

    private static class CleanerRunnable implements Runnable {
        private final long contextPtr;

        CleanerRunnable(long contextPtr) {
            this.contextPtr = contextPtr;
        }

        @Override
        public void run() {
            if (contextPtr != 0) {
                nativeFree(contextPtr);
            }
        }
    }

    private native void nativeInit(String algorithm);
    private native void nativeUpdate(long contextPtr, byte[] data, int offset, int length);
    private native byte[] nativeDoFinal(long contextPtr);
    private static native void nativeFree(long contextPtr);
    private native long getContextPtr();

    public MessageDigest(String algorithm) {
        this.algorithm = algorithm;
        nativeInit(algorithm);
        this.contextPtr = getContextPtr();
        this.cleanerRunnable = new CleanerRunnable(contextPtr);
        CLEANER.register(this, cleanerRunnable);
    }

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        nativeUpdate(contextPtr, data, 0, data.length);
    }

    public void update(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        nativeUpdate(contextPtr, data, offset, length);
    }

    public byte[] doFinal() {
        return nativeDoFinal(contextPtr);
    }

    public byte[] digest(byte[] data) {
        update(data);
        return doFinal();
    }

    public static byte[] hash(String algorithm, byte[] data) {
        MessageDigest md = new MessageDigest(algorithm);
        return md.digest(data);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getDigestLength() {
        switch (algorithm.toUpperCase()) {
            case "SHA-1":
                return 20;
            case "SHA-224":
                return 28;
            case "SHA-256":
                return 32;
            case "SHA-384":
                return 48;
            case "SHA-512":
                return 64;
            case "SHA3-224":
                return 28;
            case "SHA3-256":
                return 32;
            case "SHA3-384":
                return 48;
            case "SHA3-512":
                return 64;
            case "SM3":
                return 32;
            default:
                throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        }
    }
}
