package org.openhitls.crypto.core.symmetric;

import org.openhitls.crypto.NativeLoader;

import java.util.Arrays;

public class SM4 {
    // Algorithm modes from crypt_algid.h
    public static final int SM4_ECB = 10501;  // BSL_CID_SM4_ECB
    public static final int SM4_CBC = 10502;  // BSL_CID_SM4_CBC
    public static final int SM4_CTR = 10503;  // BSL_CID_SM4_CTR
    public static final int SM4_GCM = 10504;  // BSL_CID_SM4_GCM
    public static final int SM4_CFB = 10505;  // BSL_CID_SM4_CFB
    public static final int SM4_OFB = 10506;  // BSL_CID_SM4_OFB
    public static final int SM4_XTS = 10507;  // BSL_CID_SM4_XTS

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

    private long contextPtr;
    private int algorithm;
    private int paddingType;
    private boolean isEncryption;
    private byte[] key;
    private byte[] iv;

    public SM4(int algorithm, byte[] key, byte[] iv, int mode) {
        this(algorithm, key, iv, mode, PADDING_NONE);
    }

    public SM4(int algorithm, byte[] key, byte[] iv, int mode, int padding) {
        if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
            throw new IllegalArgumentException("Mode must be either MODE_ENCRYPT or MODE_DECRYPT");
        }
        if (padding < PADDING_NONE || padding > PADDING_PKCS7) {
            throw new IllegalArgumentException("Invalid padding mode");
        }

        // XTS mode requires a double-length key (32 bytes)
        if (algorithm == SM4_XTS) {
            if (key == null || key.length != 32) {
                throw new IllegalArgumentException("XTS mode requires a 32-byte key (two 16-byte keys)");
            }
        } else {
            if (key == null || key.length != 16) {
                throw new IllegalArgumentException("Key must be 16 bytes");
            }
        }
        
        // IV validation based on mode
        if (algorithm == SM4_CBC || algorithm == SM4_CFB || algorithm == SM4_OFB || algorithm == SM4_CTR || algorithm == SM4_GCM) {
            if (iv == null || iv.length != 16) {
                throw new IllegalArgumentException("IV must be 16 bytes for CBC/CFB/OFB/CTR/GCM modes");
            }
        } else if (algorithm == SM4_XTS) {
            if (iv == null || iv.length != 16) {
                throw new IllegalArgumentException("Tweak value must be 16 bytes for XTS mode");
            }
        }
        
        this.algorithm = algorithm;
        this.key = key.clone();
        this.iv = iv != null ? iv.clone() : null;
        this.isEncryption = (mode == MODE_ENCRYPT);
        this.paddingType = padding;
        
        nativeInit(algorithm, this.key, this.iv, mode);
        
        // Only set padding for block cipher modes (ECB and CBC)
        if (algorithm == SM4_ECB || algorithm == SM4_CBC) {
            nativeSetPadding(this.paddingType);
        }
    }

    private void setPadding(int paddingType) {
        if (paddingType < PADDING_NONE || paddingType > PADDING_PKCS7) {
            throw new IllegalArgumentException("Invalid padding mode");
        }
        this.paddingType = paddingType;
        nativeSetPadding(paddingType);
    }

    // Native method declarations
    private native void nativeInit(int algorithm, byte[] key, byte[] iv, int mode);
    private native void nativeSetPadding(int paddingType);
    private native void nativeEncryptUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, int[] outLen);
    private native void nativeDecryptUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, int[] outLen);
    private native byte[] nativeEncryptFinal();
    private native byte[] nativeDecryptFinal();
    private native void nativeReinit();
    private native int nativeGetBlockSize();

    public byte[] encryptUpdate(byte[] input, int inputOffset, int inputLen) {
        if (!isEncryption) {
            throw new IllegalStateException("Cipher not initialized for encryption");
        }
        if (input == null) {
            throw new IllegalArgumentException("Input buffer cannot be null");
        }
        if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException("Invalid input offset or length");
        }
        
        // Allocate output buffer for encrypted data
        byte[] output = new byte[inputLen + 16]; // Allow for padding
        int[] outLen = new int[1];
        nativeEncryptUpdate(input, inputOffset, inputLen, output, 0, outLen);
        return Arrays.copyOf(output, outLen[0]); // Return only the actual encrypted data
    }

    public byte[] decryptUpdate(byte[] input, int inputOffset, int inputLen) {
        if (isEncryption) {
            throw new IllegalStateException("Cipher not initialized for decryption");
        }
        if (input == null) {
            throw new IllegalArgumentException("Input buffer cannot be null");
        }
        if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException("Invalid input offset or length");
        }
        
        // Allocate output buffer for decrypted data
        byte[] output = new byte[inputLen];
        int[] outLen = new int[1];
        nativeDecryptUpdate(input, inputOffset, inputLen, output, 0, outLen);
        return Arrays.copyOf(output, outLen[0]); // Return only the actual decrypted data
    }

    public byte[] encryptFinal() {
        if (!isEncryption) {
            throw new IllegalStateException("Cipher not initialized for encryption");
        }
        byte[] finalBlock = nativeEncryptFinal();
        return finalBlock;
    }

    public byte[] decryptFinal() {
        if (isEncryption) {
            throw new IllegalStateException("Cipher not initialized for decryption");
        }
        byte[] finalBlock = nativeDecryptFinal();
        return finalBlock;
    }

    private void reinit() {
        nativeInit(algorithm, key, iv, MODE_ENCRYPT);
        nativeSetPadding(paddingType);
    }

    public int getBlockSize() {
        return nativeGetBlockSize();
    }
}
