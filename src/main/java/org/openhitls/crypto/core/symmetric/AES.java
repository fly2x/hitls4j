package org.openhitls.crypto.core.symmetric;

import org.openhitls.crypto.exception.CryptoException;
import java.lang.ref.Cleaner;

public class AES {
    private static final Cleaner CLEANER = Cleaner.create();
    private final Cleaner.Cleanable cleanable;
    private final long nativeContext;

    private static class CleanerRunnable implements Runnable {
        private final long nativeContext;

        CleanerRunnable(long nativeContext) {
            this.nativeContext = nativeContext;
        }

        @Override
        public void run() {
            if (nativeContext != 0) {
                nativeFree(nativeContext);
            }
        }
    }

    // AES modes
    public static final int MODE_ECB = 1;
    public static final int MODE_CBC = 2;
    public static final int MODE_CTR = 3;
    public static final int MODE_GCM = 4;
    public static final int MODE_CFB = 5;
    public static final int MODE_OFB = 6;

    // Operation modes
    public static final int MODE_ENCRYPT = 1;
    public static final int MODE_DECRYPT = 2;

    // Key sizes
    public static final int KEY_SIZE_128 = 128;
    public static final int KEY_SIZE_192 = 192;
    public static final int KEY_SIZE_256 = 256;

    public AES(int mode, int keySize, byte[] key, byte[] iv, int opmode) throws CryptoException {
        if (key == null) {
            throw new CryptoException("Key cannot be null");
        }

        if (keySize != KEY_SIZE_128 && keySize != KEY_SIZE_192 && keySize != KEY_SIZE_256) {
            throw new CryptoException("Invalid key size: " + keySize + " bits. Must be 128, 192, or 256 bits.");
        }

        if (key.length * 8 != keySize) {
            throw new CryptoException("Key length " + (key.length * 8) + " bits does not match specified key size " + keySize + " bits");
        }

        this.nativeContext = nativeInit(mode, key, iv, opmode, keySize);
        if (this.nativeContext == 0) {
            throw new CryptoException("Failed to initialize AES");
        }

        this.cleanable = CLEANER.register(this, new CleanerRunnable(this.nativeContext));
    }

    public void update(byte[] input, int inputOffset, int inputLen,
                      byte[] output, int outputOffset) throws CryptoException {
        if (nativeContext == 0) {
            throw new CryptoException("AES context is not initialized");
        }
        nativeUpdate(nativeContext, input, inputOffset, inputLen, output, outputOffset);
    }

    public byte[] doFinal() throws CryptoException {
        if (nativeContext == 0) {
            throw new CryptoException("AES context is not initialized");
        }
        return nativeFinal(nativeContext);
    }

    private native long nativeInit(int mode, byte[] key, byte[] iv, int opmode, int keySize);
    private native void nativeUpdate(long handle, byte[] input, int inputOffset, int inputLen,
                                   byte[] output, int outputOffset);
    private native byte[] nativeFinal(long handle);
    private static native void nativeFree(long handle);
}
