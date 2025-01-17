package org.openhitls.crypto;

import org.junit.BeforeClass;
import java.io.File;

public class BaseTest {
    @BeforeClass
    public static void loadNativeLibraries() {
        String libraryPath = new File(System.getProperty("user.dir") + "/target/native/libhitls_crypto_jni.so").getAbsolutePath();
        try {
            System.load(libraryPath);
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load native library: " + e.getMessage());
            throw e;
        }
    }
}
