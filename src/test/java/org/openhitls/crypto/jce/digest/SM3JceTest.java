package org.openhitls.crypto.jce.digest;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import java.security.MessageDigest;
import java.security.Security;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;

public class SM3JceTest extends org.openhitls.crypto.BaseTest {
    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testSM3SingleShot() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
        String message = "Hello, SM3!";
        byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));

        // Verify hash length
        assertEquals("Hash length should be 32 bytes", 32, hash.length);
    }

    @Test
    public void testSM3Incremental() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
        String part1 = "Hello, ";
        String part2 = "SM3!";

        // Incremental update
        md.update(part1.getBytes(StandardCharsets.UTF_8));
        md.update(part2.getBytes(StandardCharsets.UTF_8));
        byte[] incrementalHash = md.digest();

        // Compare with single-shot hash
        md.reset();
        byte[] singleHash = md.digest((part1 + part2).getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Incremental and single-shot hashes should match", singleHash, incrementalHash);
    }

    @Test
    public void testEmptyString() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
        byte[] hash = md.digest(new byte[0]);
        assertEquals("Hash length should be 32 bytes", 32, hash.length);
    }

    @Test
    public void testReset() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
        String message = "Test message";
        byte[] hash1 = md.digest(message.getBytes(StandardCharsets.UTF_8));

        // Get another hash after reset
        md.reset();
        byte[] hash2 = md.digest(message.getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Hashes should be identical after reset", hash1, hash2);
    }

    @Test
    public void testMultiThread() throws Exception {
        final String message = "Test message";
        final byte[] expectedHash = MessageDigest.getInstance("SM3", "HITLS4J")
            .digest(message.getBytes(StandardCharsets.UTF_8));

        Thread[] threads = new Thread[2];
        final boolean[] results = new boolean[threads.length];

        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
                    byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
                    results[index] = java.util.Arrays.equals(expectedHash, hash);
                } catch (Exception e) {
                    results[index] = false;
                }
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        for (boolean result : results) {
            assertTrue("Hash computation should be thread-safe", result);
        }
    }

    @Test
    public void testMultiThreaded() throws Exception {
        final int threadCount = 4;
        final int iterationsPerThread = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch latch = new CountDownLatch(threadCount);
        final Exception[] threadExceptions = new Exception[threadCount];
        final String testData = "Test data for multi-threaded SM3 hashing";
        
        // First get the expected hash
        MessageDigest reference = MessageDigest.getInstance("SM3", "HITLS4J");
        final byte[] expectedHash = reference.digest(testData.getBytes(StandardCharsets.UTF_8));

        for (int i = 0; i < threadCount; i++) {
            final int threadIndex = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < iterationsPerThread; j++) {
                        MessageDigest md = MessageDigest.getInstance("SM3", "HITLS4J");
                        byte[] hash = md.digest(testData.getBytes(StandardCharsets.UTF_8));
                        if (!java.util.Arrays.equals(expectedHash, hash)) {
                            throw new AssertionError("Hash mismatch in thread " + threadIndex);
                        }

                        // Also test incremental updates
                        md.reset();
                        md.update("Test ".getBytes(StandardCharsets.UTF_8));
                        md.update("data ".getBytes(StandardCharsets.UTF_8));
                        md.update("for ".getBytes(StandardCharsets.UTF_8));
                        md.update("multi-threaded ".getBytes(StandardCharsets.UTF_8));
                        md.update("SM3 ".getBytes(StandardCharsets.UTF_8));
                        md.update("hashing".getBytes(StandardCharsets.UTF_8));
                        hash = md.digest();
                        if (!java.util.Arrays.equals(expectedHash, hash)) {
                            throw new AssertionError("Incremental hash mismatch in thread " + threadIndex);
                        }
                    }
                } catch (Exception e) {
                    threadExceptions[threadIndex] = e;
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue("Threads did not complete in time", 
                  latch.await(30, TimeUnit.SECONDS));
        executor.shutdown();
        assertTrue("Executor did not shut down cleanly", 
                  executor.awaitTermination(5, TimeUnit.SECONDS));

        // Check for any exceptions that occurred in the threads
        for (int i = 0; i < threadCount; i++) {
            if (threadExceptions[i] != null) {
                throw new AssertionError("Exception in thread " + i, threadExceptions[i]);
            }
        }
    }
}
