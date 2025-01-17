package org.openhitls.crypto.jce.mac;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;

public class HMACSM3JceTest extends org.openhitls.crypto.BaseTest {
    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testHMACSM3SingleShot() throws Exception {
        byte[] key = "TestKey123".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(key, "HMACSM3");
        Mac mac = Mac.getInstance("HMACSM3", "HITLS4J");
        mac.init(keySpec);

        String message = "Hello, HMAC-SM3!";
        byte[] macResult = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Verify MAC length
        assertEquals("MAC length should be 32 bytes", 32, macResult.length);
    }

    @Test
    public void testHMACSM3Incremental() throws Exception {
        byte[] key = "TestKey123".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(key, "HMACSM3");
        Mac mac = Mac.getInstance("HMACSM3", "HITLS4J");
        mac.init(keySpec);

        String part1 = "Hello, ";
        String part2 = "HMAC-SM3!";

        // Incremental update
        mac.update(part1.getBytes(StandardCharsets.UTF_8));
        mac.update(part2.getBytes(StandardCharsets.UTF_8));
        byte[] incrementalMac = mac.doFinal();

        // Compare with single-shot MAC
        mac.reset();
        byte[] singleMac = mac.doFinal((part1 + part2).getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Incremental and single-shot MACs should match", singleMac, incrementalMac);
    }

    @Test
    public void testEmptyMessage() throws Exception {
        byte[] key = "TestKey123".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(key, "HMACSM3");
        Mac mac = Mac.getInstance("HMACSM3", "HITLS4J");
        mac.init(keySpec);

        byte[] macResult = mac.doFinal(new byte[0]);
        assertEquals("MAC length should be 32 bytes", 32, macResult.length);
    }

    @Test
    public void testReset() throws Exception {
        byte[] key = "TestKey123".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(key, "HMACSM3");
        Mac mac = Mac.getInstance("HMACSM3", "HITLS4J");
        mac.init(keySpec);

        String message = "Test message";
        byte[] mac1 = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Get another MAC after reset
        mac.reset();
        byte[] mac2 = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("MACs should be identical after reset", mac1, mac2);
    }

    @Test
    public void testMultiThread() throws Exception {
        final int threadCount = 4;
        final int iterationsPerThread = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch latch = new CountDownLatch(threadCount);
        final Exception[] threadExceptions = new Exception[threadCount];
        
        final String message = "Test message for multi-threaded HMAC-SM3";
        final byte[] key = "TestKey123".getBytes(StandardCharsets.UTF_8);
        final SecretKeySpec keySpec = new SecretKeySpec(key, "HMACSM3");

        // Get expected MAC
        Mac mac = Mac.getInstance("HMACSM3", "HITLS4J");
        mac.init(keySpec);
        final byte[] expectedMac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        for (int i = 0; i < threadCount; i++) {
            final int threadIndex = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < iterationsPerThread; j++) {
                        // Test single-shot MAC
                        Mac threadMac = Mac.getInstance("HMACSM3", "HITLS4J");
                        threadMac.init(keySpec);
                        byte[] threadMacResult = threadMac.doFinal(message.getBytes(StandardCharsets.UTF_8));
                        if (!java.util.Arrays.equals(expectedMac, threadMacResult)) {
                            throw new AssertionError("MAC mismatch in thread " + threadIndex);
                        }

                        // Test incremental updates
                        threadMac.reset();
                        threadMac.update("Test ".getBytes(StandardCharsets.UTF_8));
                        threadMac.update("message ".getBytes(StandardCharsets.UTF_8));
                        threadMac.update("for ".getBytes(StandardCharsets.UTF_8));
                        threadMac.update("multi-threaded ".getBytes(StandardCharsets.UTF_8));
                        threadMac.update("HMAC-".getBytes(StandardCharsets.UTF_8));
                        threadMac.update("SM3".getBytes(StandardCharsets.UTF_8));
                        byte[] incrementalMac = threadMac.doFinal();
                        if (!java.util.Arrays.equals(expectedMac, incrementalMac)) {
                            throw new AssertionError("Incremental MAC mismatch in thread " + threadIndex);
                        }

                        // Test reset functionality
                        threadMac.reset();
                        threadMac.update(message.getBytes(StandardCharsets.UTF_8));
                        byte[] resetMac = threadMac.doFinal();
                        if (!java.util.Arrays.equals(expectedMac, resetMac)) {
                            throw new AssertionError("Reset MAC mismatch in thread " + threadIndex);
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
