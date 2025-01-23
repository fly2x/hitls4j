package org.openhitls.crypto.jce.provider;

import org.openhitls.crypto.jce.cipher.SM4Cipher;
import java.security.Provider;
import org.openhitls.crypto.jce.key.generator.SM2KeyPairGenerator;
import org.openhitls.crypto.jce.key.factory.SM2KeyFactory;
import org.openhitls.crypto.jce.cipher.SM2Cipher;
import org.openhitls.crypto.jce.signer.SM2Signature;
import org.openhitls.crypto.jce.key.generator.SM4KeyGenerator;

public final class HiTls4jProvider extends Provider {
    public static final String PROVIDER_NAME = "HITLS4J";
    public static final double VERSION = 1.0;
    public static final String INFO = "HiTls4j Cryptographic Provider v1.0";

    public static class SM4CipherImpl extends SM4Cipher {
        public SM4CipherImpl() {
            super();
        }
    }

    public static class SM4CipherOidImpl extends SM4Cipher {
        public SM4CipherOidImpl(String transformation) throws Exception {
            super();
            String[] parts = transformation.split("/");
            if (parts.length > 1) {
                engineSetMode(parts[1]);
            }
            if (parts.length > 2) {
                engineSetPadding(parts[2]);
            }
        }
    }

    public HiTls4jProvider() {
        super(PROVIDER_NAME, VERSION, INFO);
        
        // Register symmetric ciphers
        put("Cipher.SM4", SM4CipherImpl.class.getName());
        put("Cipher.AES", "org.openhitls.crypto.jce.cipher.HiTlsAES");
        put("Cipher.SM4 SupportedModes", "ECB|CBC|CTR|GCM|CFB|OFB|XTS");
        put("Cipher.SM4 SupportedPaddings", "NOPADDING|PKCS5PADDING|PKCS7PADDING|ZEROSPADDING|ISO7816PADDING|X923PADDING");

        // Register SM2 services
        put("KeyPairGenerator.SM2", SM2KeyPairGenerator.class.getName());
        put("KeyFactory.SM2", SM2KeyFactory.class.getName());
        put("Cipher.SM2", SM2Cipher.class.getName());
        put("Signature.SM2", SM2Signature.class.getName());

        // Register SM2 as EC
        put("KeyPairGenerator.EC", SM2KeyPairGenerator.class.getName());
        put("KeyFactory.EC", SM2KeyFactory.class.getName());
        put("Cipher.EC", SM2Cipher.class.getName());
        put("Signature.EC", SM2Signature.class.getName());
        put("Signature.SM3withSM2", SM2Signature.class.getName());
        put("AlgorithmParameters.EC", ECParameters.class.getName());
        put("AlgorithmParameterGenerator.EC", "sun.security.ec.ECParameterGenerator");
        put("KeyAgreement.EC", "sun.security.ec.ECDHKeyAgreement");

        // Register specific transformations
        // ECB mode
        put("Cipher.SM4/ECB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/NOPADDING");
        put("Cipher.SM4/ECB/PKCS5PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/PKCS5PADDING");
        put("Cipher.SM4/ECB/PKCS7PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/PKCS7PADDING");
        put("Cipher.SM4/ECB/ZEROSPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/ZEROSPADDING");
        put("Cipher.SM4/ECB/ISO7816PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/ISO7816PADDING");
        put("Cipher.SM4/ECB/X923PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/ECB/X923PADDING");
        
        // CBC mode
        put("Cipher.SM4/CBC/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/NOPADDING");
        put("Cipher.SM4/CBC/PKCS5PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/PKCS5PADDING");
        put("Cipher.SM4/CBC/PKCS7PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/PKCS7PADDING");
        put("Cipher.SM4/CBC/ZEROSPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/ZEROSPADDING");
        put("Cipher.SM4/CBC/ISO7816PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/ISO7816PADDING");
        put("Cipher.SM4/CBC/X923PADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CBC/X923PADDING");

        // CTR mode (stream cipher, no padding needed)
        put("Cipher.SM4/CTR/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CTR/NOPADDING");

        // GCM mode (authenticated encryption)
        put("Cipher.SM4/GCM/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/GCM/NOPADDING");

        // CFB mode (stream cipher)
        put("Cipher.SM4/CFB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/CFB/NOPADDING");

        // OFB mode (stream cipher)
        put("Cipher.SM4/OFB/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/OFB/NOPADDING");

        // XTS mode
        put("Cipher.SM4/XTS/NOPADDING", "org.openhitls.crypto.jce.HiTls4jProvider$SM4CipherOidImpl SM4/XTS/NOPADDING");

        // Register message digests
        put("MessageDigest.SHA-1", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA1");
        put("MessageDigest.SHA-224", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA224");
        put("MessageDigest.SHA-256", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA256");
        put("MessageDigest.SHA-384", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA384");
        put("MessageDigest.SHA-512", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA512");
        put("MessageDigest.SHA3-224", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA3_224");
        put("MessageDigest.SHA3-256", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA3_256");
        put("MessageDigest.SHA3-384", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA3_384");
        put("MessageDigest.SHA3-512", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SHA3_512");
        put("MessageDigest.SM3", "org.openhitls.crypto.jce.digest.HiTlsMessageDigest$SM3");
        
        // Register algorithm aliases
        put("Alg.Alias.MessageDigest.SHA224", "SHA-224");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");

        // Register HMAC implementations
        put("Mac.HMACSHA1", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA1");
        put("Mac.HMACSHA224", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA224");
        put("Mac.HMACSHA256", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA256");
        put("Mac.HMACSHA384", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA384");
        put("Mac.HMACSHA512", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA512");
        put("Mac.HMACSHA3-224", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA3_224");
        put("Mac.HMACSHA3-256", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA3_256");
        put("Mac.HMACSHA3-384", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA3_384");
        put("Mac.HMACSHA3-512", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSHA3_512");
        put("Mac.HMACSM3", "org.openhitls.crypto.jce.mac.HiTlsHMAC$HMACSM3");

        // Register HMAC algorithm aliases
        put("Alg.Alias.Mac.HMAC-SHA1", "HMACSHA1");
        put("Alg.Alias.Mac.HMAC-SHA224", "HMACSHA224");
        put("Alg.Alias.Mac.HMAC-SHA256", "HMACSHA256");
        put("Alg.Alias.Mac.HMAC-SHA384", "HMACSHA384");
        put("Alg.Alias.Mac.HMAC-SHA512", "HMACSHA512");
        put("Alg.Alias.Mac.HMAC-SHA3-224", "HMACSHA3-224");
        put("Alg.Alias.Mac.HMAC-SHA3-256", "HMACSHA3-256");
        put("Alg.Alias.Mac.HMAC-SHA3-384", "HMACSHA3-384");
        put("Alg.Alias.Mac.HMAC-SHA3-512", "HMACSHA3-512");
        put("Alg.Alias.Mac.HMAC-SM3", "HMACSM3");

        // Register SM4 key generator
        put("KeyGenerator.SM4", SM4KeyGenerator.class.getName());
    }
}