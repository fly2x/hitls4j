package org.openhitls.crypto.core.symmetric;

import java.util.Arrays;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class SymmetricCipherImpl extends NativeResource {
    // Operation modes
    public static final int MODE_ENCRYPT = 1;
    public static final int MODE_DECRYPT = 2;

    // Padding constants from crypt_types.h
    public static final int PADDING_NONE = 0;      // CRYPT_PADDING_NONE
    public static final int PADDING_ZEROS = 1;     // CRYPT_PADDING_ZEROS
    public static final int PADDING_ISO7816 = 2;   // CRYPT_PADDING_ISO7816
    public static final int PADDING_X923 = 3;      // CRYPT_PADDING_X923
    public static final int PADDING_PKCS5 = 4;     // CRYPT_PADDING_PKCS5
    public static final int PADDING_PKCS7 = 5;     // CRYPT_PADDING_PKCS7

    public SymmetricCipherImpl(String algorithm, String cipherMode,byte[] key, byte[] iv, int mode) {
        this(algorithm, cipherMode, key, iv, mode, PADDING_NONE);
    }
    
    public SymmetricCipherImpl(String algorithm, String cipherMode, byte[] key, byte[] iv, int mode, int padding) {
        super(initContext(algorithm, cipherMode, key, iv, mode, padding), CryptoNative::symmetricCipherFree);
    }

    private static long initContext(String algorithm, String cipherMode, byte[] key, byte[] iv, int mode, int padding) {
        if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
            throw new IllegalArgumentException("Mode must be either MODE_ENCRYPT or MODE_DECRYPT");
        }
        if (padding < PADDING_NONE || padding > PADDING_PKCS7) {
            throw new IllegalArgumentException("Invalid padding mode");
        }

        // XTS mode requires a double-length key (32 bytes)
        if ("SM4".equals(algorithm)) {
            if ("XTS".equals(cipherMode)) {
                if (key == null || key.length != 32) {
                    throw new IllegalArgumentException("XTS mode requires a 32-byte key (two 16-byte keys)");
                }
            } else {
                if (key == null || key.length != 16) {
                    throw new IllegalArgumentException("Key must be 16 bytes");
                }
            }
            // IV validation based on mode
            if ("CBC".equals(cipherMode) || "CFB".equals(cipherMode) || "OFB".equals(cipherMode) || "CTR".equals(cipherMode) || "GCM".equals(cipherMode)) {
                if (iv == null || iv.length != 16) {
                    throw new IllegalArgumentException("IV must be 16 bytes for CBC/CFB/OFB/CTR/GCM modes");
                }
            } else if ("XTS".equals(cipherMode)) {  
                if (iv == null || iv.length != 16) {
                    throw new IllegalArgumentException("Tweak value must be 16 bytes for XTS mode");
                }
            }
        }
        

    
        long contextPtr = CryptoNative.symmetricCipherInit(algorithm, cipherMode, key, iv, mode);
        // Only set padding for block cipher modes (ECB and CBC)
        if ("ECB".equals(cipherMode) || "CBC".equals(cipherMode)) {
            CryptoNative.symmetricCipherSetPadding(contextPtr, padding);
        }
        return contextPtr;
    }

    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        if (input == null) {
            throw new IllegalArgumentException("Input buffer cannot be null");
        }
        if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException("Invalid input offset or length");
        }
        
        // Allocate output buffer for encrypted data
        byte[] output = new byte[inputLen + 16]; // Allow for padding
        int[] outLen = new int[1];
        CryptoNative.symmetricCipherUpdate(nativeContext, input, inputOffset, inputLen, output, 0, outLen);
        return Arrays.copyOf(output, outLen[0]); // Return only the actual encrypted data
    }

    public byte[] doFinal() {
        byte[] finalBlock = CryptoNative.symmetricCipherFinal(nativeContext);
        return finalBlock;
    }
}