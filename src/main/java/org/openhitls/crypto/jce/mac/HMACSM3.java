package org.openhitls.crypto.jce.mac;

import org.openhitls.crypto.core.mac.HMAC;
import javax.crypto.MacSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class HMACSM3 extends MacSpi {
    private HMAC hmac;
    private int macLength = 32; // SM3 hash length is 32 bytes
    private byte[] keyBytes; // Store key for reinit

    public HMACSM3() {
        // Don't initialize HMAC here, wait for key in engineInit
    }

    @Override
    protected int engineGetMacLength() {
        return macLength;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        if (!(key instanceof SecretKeySpec)) {
            throw new InvalidKeyException("Key must be a SecretKeySpec");
        }

        SecretKeySpec keySpec = (SecretKeySpec) key;
        if (!"HMACSM3".equalsIgnoreCase(keySpec.getAlgorithm())) {
            throw new InvalidKeyException("Wrong algorithm: " + keySpec.getAlgorithm() + ". Key algorithm must be HMACSM3");
        }

        keyBytes = keySpec.getEncoded();
        if (keyBytes == null || keyBytes.length == 0) {
            throw new InvalidKeyException("Empty key");
        }

        try {
            hmac = new HMAC(HMAC.HMAC_SM3, keyBytes);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize HMAC-SM3: " + e.getMessage());
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] data = new byte[]{input};
        engineUpdate(data, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        // Check for null input first
        if (input == null) {
            throw new IllegalArgumentException("Input buffer cannot be null");
        }
        
        // Then check initialization
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        
        // Then check bounds
        if (offset < 0 || len < 0 || offset + len > input.length) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        
        // Skip empty updates
        if (len == 0) {
            return;
        }

        hmac.update(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        return hmac.doFinal();
    }

    @Override
    protected void engineReset() {
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        hmac.reinit();
    }
}
