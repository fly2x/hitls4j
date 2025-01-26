package org.openhitls.crypto;

import org.junit.BeforeClass;
import java.io.File;
import java.security.Security;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class BaseTest {
    @BeforeClass
    public static void loadNativeLibraries() {
        String libraryPath = new File(System.getProperty("user.dir") + "/target/native/libhitls_crypto_jni.so").getAbsolutePath();
        System.load(libraryPath);
        Security.addProvider(new HiTls4jProvider());
    }
}
