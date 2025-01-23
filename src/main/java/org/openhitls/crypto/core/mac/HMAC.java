package org.openhitls.crypto.core.mac;

import java.lang.ref.Cleaner;

public class HMAC {
    private static final Cleaner CLEANER = Cleaner.create();
    private final long contextPtr;
    private final CleanerRunnable cleanerRunnable;

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

    // Native method declarations
    private native long nativeInit(int algorithm, byte[] key);
    private native void nativeUpdate(long contextPtr, byte[] data, int offset, int length);
    private native byte[] nativeDoFinal(long contextPtr);
    private native void nativeReinit(long contextPtr);
    private native int nativeGetMacLength(long contextPtr);
    private static native void nativeFree(long contextPtr);

    // Algorithm constants from crypt_algid.h
    public static final int HMAC_SM3 = 10511; // BSL_CID_HMAC_SM3 from crypt_algid.h

    public HMAC(int algorithm, byte[] key) {
        this.contextPtr = nativeInit(algorithm, key);
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

    public void reinit() {
        nativeReinit(contextPtr);
    }

    public int getMacLength() {
        return nativeGetMacLength(contextPtr);
    }

    // Convenience method to compute HMAC in one call
    public static byte[] compute(int algorithm, byte[] key, byte[] data) {
        HMAC hmac = new HMAC(algorithm, key);
        hmac.update(data);
        return hmac.doFinal();
    }
}
