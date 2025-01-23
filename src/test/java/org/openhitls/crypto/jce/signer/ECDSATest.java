package org.openhitls.crypto.jce.signer;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class ECDSATest {
    private static final Provider provider = new HiTls4jProvider();
    private static final String[] SUPPORTED_CURVES = {
        "secp256r1", // NIST P-256
        "secp384r1", // NIST P-384
        "secp521r1", // NIST P-521
        "sm2p256v1"  // SM2 curve
    };

    // NIST P-256 test vectors
    private static final String P256_D = "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464";
    private static final String P256_Qx = "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83";
    private static final String P256_Qy = "ce4014c68811f9a21a1fef472be96946fe8d9b7d7d83c2d6787a0cfbd0a3fa03";
    private static final String P256_MSG = "sample";
    private static final String P256_K = "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de";
    private static final String P256_R = "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac";
    private static final String P256_S = "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903";

    // NIST P-384 test vectors
    private static final String P384_D = "a857d9f0f1c9f4f3b4a5c3a0f339daf7b11d3d9c3a7c39d5c1c92614219bf02a8076c827a42c0a0a785a878c04c0c293";
    private static final String P384_Qx = "8d999057ba3f2e07cdb1f44982639e8f39c7c6f4b1d0e990da943bf3b1a70385f4619314319dfa46";
    private static final String P384_Qy = "1b43f3a5a203e3b6d27a3fc16e0eb8f5e1d2f31c3caad3c64e7ea8c6f3e3a503f9d76572d6c56e107";
    private static final String P384_MSG = "sample";
    private static final String P384_K = "b6e5f32f56a4c16e9c3e55298b5cdb4e7c9993e2b1c5e4a5f";
    private static final String P384_R = "8f3c1313e9cd59c9db4b12c0c9e2e3e499b5c22e8b7d9e5e";
    private static final String P384_S = "7b0f6e8c9d6bcb8bd943f68b9e46f99c2a4f3d89e41d0b48";

    @Before
    public void setUp() {
        Security.addProvider(provider);
    }

    @Test
    public void testKeyGeneration() throws Exception {
        for (String curveName : SUPPORTED_CURVES) {
            // Initialize with ECGenParameterSpec
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", provider);
            keyGen.initialize(ecParameterSpec);
            KeyPair keyPair = keyGen.generateKeyPair();

            assertNotNull("KeyPair should not be null for " + curveName, keyPair);
            assertNotNull("Public key should not be null for " + curveName, keyPair.getPublic());
            assertNotNull("Private key should not be null for " + curveName, keyPair.getPrivate());

            // Test key specs
            KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
            ECPublicKeySpec pubSpec = keyFactory.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class);
            ECPrivateKeySpec privSpec = keyFactory.getKeySpec(keyPair.getPrivate(), ECPrivateKeySpec.class);

            assertNotNull("Public key spec should not be null for " + curveName, pubSpec);
            assertNotNull("Private key spec should not be null for " + curveName, privSpec);
        }
    }

    @Test
    public void testKeyRestore() throws Exception {
        // Test P-256 key restoration
        testKeyRestoreForCurve("secp256r1", P256_Qx, P256_Qy, P256_D);
        
        // Test P-384 key restoration
        testKeyRestoreForCurve("secp384r1", P384_Qx, P384_Qy, P384_D);
    }

    private void testKeyRestoreForCurve(String curveName, String xHex, String yHex, String privateHex) 
            throws Exception {
        // Create ECPoint from coordinates
        ECPoint w = new ECPoint(new BigInteger(xHex, 16), new BigInteger(yHex, 16));

        // Get parameters
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
        params.init(new ECGenParameterSpec(curveName));
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create key specs
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
        PublicKey pubKey = keyFactory.generatePublic(pubSpec);
        PrivateKey privKey = keyFactory.generatePrivate(privSpec);

        assertNotNull("Public key should not be null for " + curveName, pubKey);
        assertNotNull("Private key should not be null for " + curveName, privKey);

        // Test key conversion back to specs
        ECPublicKeySpec pubSpecResult = keyFactory.getKeySpec(pubKey, ECPublicKeySpec.class);
        ECPrivateKeySpec privSpecResult = keyFactory.getKeySpec(privKey, ECPrivateKeySpec.class);

        assertEquals("X coordinate should match for " + curveName, 
                w.getAffineX(), pubSpecResult.getW().getAffineX());
        assertEquals("Y coordinate should match for " + curveName, 
                w.getAffineY(), pubSpecResult.getW().getAffineY());
        assertEquals("Private key value should match for " + curveName, 
                new BigInteger(privateHex, 16), privSpecResult.getS());
    }

    @Test
    public void testSignatureGeneration() throws Exception {
        for (String curveName : SUPPORTED_CURVES) {
            // Initialize with ECGenParameterSpec
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

            // Generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", provider);
            keyGen.initialize(ecParameterSpec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Test data
            byte[] message = "Hello, ECDSA with curve ".concat(curveName).getBytes();

            // Sign
            Signature signer = Signature.getInstance(getSignatureAlgorithm(curveName), provider);
            signer.initSign(keyPair.getPrivate());
            signer.update(message);
            byte[] signature = signer.sign();

            // Verify
            Signature verifier = Signature.getInstance(getSignatureAlgorithm(curveName), provider);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(message);
            assertTrue("Signature verification should succeed for " + curveName, 
                    verifier.verify(signature));

            // Verify with modified message should fail
            message[0] ^= 1; // Flip one bit
            verifier.update(message);
            assertFalse("Signature verification should fail for modified message with " + curveName, 
                    verifier.verify(signature));
        }
    }

    @Test
    public void testP256KeyGeneration() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", provider);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        assertNotNull("KeyPair should not be null", keyPair);
        assertTrue("Public key should be instance of ECPublicKey", 
                keyPair.getPublic() instanceof java.security.interfaces.ECPublicKey);
        assertTrue("Private key should be instance of ECPrivateKey", 
                keyPair.getPrivate() instanceof java.security.interfaces.ECPrivateKey);
    }

    @Test
    public void testP256WithTestVectors() throws Exception {
        // Create key specs
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create private key
        BigInteger s = new BigInteger(P256_D, 16);
        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);

        // Create public key
        ECPoint w = new ECPoint(new BigInteger(P256_Qx, 16), new BigInteger(P256_Qy, 16));
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Sign
        byte[] message = P256_MSG.getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA", provider);
        signer.initSign(privKey);
        signer.update(message);
        byte[] signature = signer.sign();

        // Verify
        signer.initVerify(pubKey);
        signer.update(message);
        assertTrue("Signature verification should succeed", signer.verify(signature));
    }

    @Test
    public void testP384WithTestVectors() throws Exception {
        // Create key specs
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create private key
        BigInteger s = new BigInteger(P384_D, 16);
        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);

        // Create public key
        ECPoint w = new ECPoint(new BigInteger(P384_Qx, 16), new BigInteger(P384_Qy, 16));
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Sign
        byte[] message = P384_MSG.getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA384withECDSA", provider);
        signer.initSign(privKey);
        signer.update(message);
        byte[] signature = signer.sign();

        // Verify
        signer.initVerify(pubKey);
        signer.update(message);
        assertTrue("Signature verification should succeed", signer.verify(signature));
    }

    @Test
    public void testInteroperability() throws Exception {
        // Test interoperability between curves
        String[] curves = {"secp256r1", "secp384r1", "secp521r1", "sm2p256v1"};
        String[] messages = {
            "Short message",
            "Medium length message for testing ECDSA signatures",
            "A longer message that will be used to test ECDSA signatures with different curves and ensure compatibility"
        };

        for (String curve : curves) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", provider);
            keyGen.initialize(new ECGenParameterSpec(curve));
            KeyPair keyPair = keyGen.generateKeyPair();

            String sigAlg = getSignatureAlgorithm(curve);
            Signature signer = Signature.getInstance(sigAlg, provider);

            for (String message : messages) {
                byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);

                // Sign
                signer.initSign(keyPair.getPrivate());
                signer.update(msgBytes);
                byte[] signature = signer.sign();

                // Verify
                signer.initVerify(keyPair.getPublic());
                signer.update(msgBytes);
                assertTrue(String.format("Signature verification failed for curve %s", curve),
                        signer.verify(signature));

                // Verify signature with modified message should fail
                msgBytes[0] ^= 1;
                signer.update(msgBytes);
                assertFalse(String.format("Signature verification should fail for modified message with curve %s", curve),
                        signer.verify(signature));
            }
        }
    }

    private String getSignatureAlgorithm(String curve) {
        switch (curve) {
            case "sm2p256v1":
                return "SM3withSM2";
            case "secp256r1":
                return "SHA256withECDSA";
            case "secp384r1":
                return "SHA384withECDSA";
            case "secp521r1":
                return "SHA512withECDSA";
            default:
                return "SHA256withECDSA";
        }
    }
} 