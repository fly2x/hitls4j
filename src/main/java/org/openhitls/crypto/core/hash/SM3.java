package org.openhitls.crypto.core.hash;

import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.Cleaner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class SM3 {
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

    private native void nativeInit();
    private native void nativeUpdate(long contextPtr, byte[] data, int offset, int length);
    private native byte[] nativeDoFinal(long contextPtr);
    private static native void nativeFree(long contextPtr);

    public SM3() {
        nativeInit();
        this.contextPtr = getContextPtr();
        this.cleanerRunnable = new CleanerRunnable(contextPtr);
        CLEANER.register(this, cleanerRunnable);
    }

    private native long getContextPtr();

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        nativeUpdate(contextPtr, data, 0, data.length);
    }

    public byte[] doFinal() {
        return nativeDoFinal(contextPtr);
    }

    public static byte[] hash(byte[] data) {
        SM3 sm3 = new SM3();
        sm3.update(data);
        return sm3.doFinal();
    }
}
