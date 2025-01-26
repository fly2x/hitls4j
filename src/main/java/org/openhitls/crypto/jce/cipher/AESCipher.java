package org.openhitls.crypto.jce.cipher;

import java.security.InvalidKeyException;

public class AESCipher extends AbstractBlockCipher {
    
    @Override
    public String getAlgorithmName() {
        return "AES";
    }
    
    @Override
    public void validateKeySize(byte[] keyBytes) throws InvalidKeyException {
        if (keyBytes == null || (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)) {
            throw new InvalidKeyException("Key must be 16, 24 or 32 bytes");
        }
    }
    
    @Override
    public String[] getSupportedModes() {
        return new String[]{"ECB", "CBC", "CTR", "GCM"};
    }
}
