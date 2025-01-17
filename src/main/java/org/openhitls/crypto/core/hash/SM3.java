package org.openhitls.crypto.core.hash;

import org.openhitls.crypto.NativeLoader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class SM3 {
    private native void nativeInit();
    private native void nativeUpdate(byte[] data, int offset, int length);
    private native byte[] nativeDoFinal();

    private long contextPtr;

    public SM3() {
        nativeInit();
    }

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        nativeUpdate(data, 0, data.length);
    }

    public byte[] doFinal() {
        return nativeDoFinal();
    }

    public static byte[] hash(byte[] data) {
        SM3 sm3 = new SM3();
        sm3.update(data);
        return sm3.doFinal();
    }
}

