package org.openhitls.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.atomic.AtomicBoolean;

public class NativeLoader {
    private static final AtomicBoolean loaded = new AtomicBoolean(false);
    private static Path tempDir;

    public static synchronized void loadLibraries() {
        if (loaded.get()) {
            return;
        }

        try {
            // Create temp directory that will be deleted on JVM exit
            tempDir = Files.createTempDirectory("hitls-native-");
            tempDir.toFile().deleteOnExit();

            // Extract and load the combined library
            Path libPath = extractLibrary("libhitls_combined.so");

            if (libPath != null) {
                System.load(libPath.toAbsolutePath().toString());
                loaded.set(true);
            } else {
                throw new IOException("Failed to extract combined library");
            }

            // Add shutdown hook for cleanup
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    if (tempDir != null) {
                        Files.walk(tempDir)
                            .sorted((a, b) -> b.compareTo(a)) // Reverse order to delete files before directories
                            .forEach(path -> {
                                try {
                                    Files.deleteIfExists(path);
                                } catch (IOException e) {
                                }
                            });
                    }
                } catch (IOException e) {
                }
            }));
        } catch (Exception e) {
            throw new RuntimeException("Failed to load native library", e);
        }
    }

    private static Path extractLibrary(String libName) throws IOException {
        Path libPath = tempDir.resolve(libName);
        String resourcePath = "/native/libs/" + libName;

        try (InputStream is = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IOException("Library not found in JAR: " + resourcePath);
            }

            Files.copy(is, libPath, StandardCopyOption.REPLACE_EXISTING);
            libPath.toFile().setExecutable(true, false);
            return libPath;
        } catch (IOException e) {
            return null;
        }
    }
}
