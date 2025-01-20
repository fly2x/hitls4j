package org.openhitls.crypto.jce.signer;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class SM2JceTest {
    private static final Provider provider = new HiTls4jProvider();

    @Before
    public void setUp() {
        Security.addProvider(provider);
    }

    @Test
    public void testSM2KeyGeneration() throws Exception {
        // Initialize with ECGenParameterSpec
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
        params.init(new ECGenParameterSpec("sm2p256v1"));
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", provider);
        keyGen.initialize(ecParameterSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        assertNotNull("KeyPair should not be null", keyPair);
        assertNotNull("Public key should not be null", keyPair.getPublic());
        assertNotNull("Private key should not be null", keyPair.getPrivate());
    }

    @Test
    public void testSM2KeyRestore() throws Exception {
        // Test values (replace with actual test vectors if available)
        String xHex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
        String yHex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
        String privateHex = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

        // Create ECPoint from coordinates
        ECPoint w = new ECPoint(new BigInteger(xHex, 16), new BigInteger(yHex, 16));

        // Get parameters
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
        params.init(new ECGenParameterSpec("sm2p256v1"));
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create key specs
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
        PublicKey pubKey = keyFactory.generatePublic(pubSpec);
        PrivateKey privKey = keyFactory.generatePrivate(privSpec);

        assertNotNull("Public key should not be null", pubKey);
        assertNotNull("Private key should not be null", privKey);

        // Test key conversion back to specs
        ECPublicKeySpec pubSpecResult = keyFactory.getKeySpec(pubKey, ECPublicKeySpec.class);
        ECPrivateKeySpec privSpecResult = keyFactory.getKeySpec(privKey, ECPrivateKeySpec.class);

        assertEquals("X coordinate should match", w.getAffineX(), pubSpecResult.getW().getAffineX());
        assertEquals("Y coordinate should match", w.getAffineY(), pubSpecResult.getW().getAffineY());
        assertEquals("Private key value should match", new BigInteger(privateHex, 16), privSpecResult.getS());
    }
}
