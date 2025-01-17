package org.openhitls.crypto.jce.provider;

import org.openhitls.crypto.jce.cipher.SM4Cipher;
import java.security.Provider;
import org.openhitls.crypto.jce.key.generator.SM2KeyPairGenerator;
import org.openhitls.crypto.jce.key.factory.SM2KeyFactory;
import org.openhitls.crypto.jce.cipher.SM2Cipher;
import org.openhitls.crypto.jce.digest.SM3MessageDigest;
import org.openhitls.crypto.jce.signer.SM2Signature;
import org.openhitls.crypto.jce.mac.HMACSM3;
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
        
        // Register SM4 Cipher
        put("Cipher.SM4", SM4CipherImpl.class.getName());
        put("Cipher.SM4 SupportedModes", "ECB|CBC|CTR|GCM|CFB|OFB|XTS");
        put("Cipher.SM4 SupportedPaddings", "NOPADDING|PKCS5PADDING|PKCS7PADDING|ZEROSPADDING|ISO7816PADDING|X923PADDING");

        // Register SM2 services
        put("KeyPairGenerator.SM2", SM2KeyPairGenerator.class.getName());
        put("KeyFactory.SM2", SM2KeyFactory.class.getName());
        put("Cipher.SM2", SM2Cipher.class.getName());
        put("Signature.SM2", SM2Signature.class.getName());

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

        // Register SM3 MessageDigest
        put("MessageDigest.SM3", SM3MessageDigest.class.getName());

        // Register HMAC-SM3
        put("Mac.HMACSM3", HMACSM3.class.getName());

        // Register KeyGenerator
        put("KeyGenerator.SM4", SM4KeyGenerator.class.getName());
    }
}
