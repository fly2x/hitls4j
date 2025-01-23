package org.openhitls.crypto.jce.digest;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.Assert.*;

public class SHA2MessageDigestJceTest {
    private static final String PROVIDER_NAME = "HITLS4J";
    private static final byte[] TEST_DATA = "Hello, World!".getBytes();

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testSHA224() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA-224", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-224 digest length should be 28 bytes", 28, digest.length);
    }

    @Test
    public void testSHA256() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA-256", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-256 digest length should be 32 bytes", 32, digest.length);
    }

    @Test
    public void testSHA384() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA-384", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-384 digest length should be 48 bytes", 48, digest.length);
    }

    @Test
    public void testSHA512() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA-512", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-512 digest length should be 64 bytes", 64, digest.length);
    }

    @Test
    public void testSHA224Alias() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA224", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-224 digest length should be 28 bytes", 28, digest.length);
    }

    @Test
    public void testSHA256Alias() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA256", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-256 digest length should be 32 bytes", 32, digest.length);
    }

    @Test
    public void testSHA384Alias() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA384", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-384 digest length should be 48 bytes", 48, digest.length);
    }

    @Test
    public void testSHA512Alias() throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA512", PROVIDER_NAME);
        byte[] digest = md.digest(TEST_DATA);
        assertEquals("SHA-512 digest length should be 64 bytes", 64, digest.length);
    }
}
