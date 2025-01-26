package org.openhitls.crypto.core;

import java.lang.ref.Cleaner;

public abstract class NativeResource {
    private static final Cleaner CLEANER = Cleaner.create();
    protected final Cleaner.Cleanable cleanable;
    protected final long nativeContext;

    protected static class CleanerRunnable implements Runnable {
        private final long nativeContext;
        private final FreeCallback freeCallback;

        CleanerRunnable(long nativeContext, FreeCallback freeCallback) {
            this.nativeContext = nativeContext;
            this.freeCallback = freeCallback;
        }

        @Override
        public void run() {
            if (nativeContext != 0) {
                freeCallback.freeNativeContext(nativeContext);
            }
        }
    }

    @FunctionalInterface
    protected interface FreeCallback {
        void freeNativeContext(long nativeContext);
    }

    protected NativeResource(long nativeContext, FreeCallback freeCallback) {
        this.nativeContext = nativeContext;
        this.cleanable = CLEANER.register(this, new CleanerRunnable(nativeContext, freeCallback));
    }
}