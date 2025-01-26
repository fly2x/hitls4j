package org.openhitls.crypto.jce.cipher;

import java.security.InvalidKeyException;

public class SM4Cipher extends AbstractBlockCipher {
    
    @Override
    public String getAlgorithmName() {
        return "SM4";
    }
    
    @Override
    public void validateKeySize(byte[] keyBytes) throws InvalidKeyException {
        if (mode.equals("XTS")) {
            if (keyBytes == null || keyBytes.length != 32) {
                throw new InvalidKeyException("XTS mode requires a 32-byte key (two 16-byte keys)");
            }
        } else {
            if (keyBytes == null || keyBytes.length != 16) {
                throw new InvalidKeyException("Key must be 16 bytes");
            }
        }
    }
    
    @Override
    public String[] getSupportedModes() {
        return new String[]{"ECB", "CBC", "CTR", "CFB", "OFB", "GCM", "XTS"};
    }
} 