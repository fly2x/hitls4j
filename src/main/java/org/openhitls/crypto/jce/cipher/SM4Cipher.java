package org.openhitls.crypto.jce.cipher;

import org.openhitls.crypto.core.symmetric.SM4;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SM4Cipher extends CipherSpi {
    private SM4 sm4;
    private int opmode;
    private byte[] key;
    private byte[] iv;
    private String mode = "ECB";
    private String padding = "NOPADDING";
    private boolean initialized = false;
    private boolean requiresIV;

    public SM4Cipher() {
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        mode = mode.toUpperCase();
        switch (mode) {
            case "ECB":
                requiresIV = false;
                break;
            case "CBC":
            case "CTR":
            case "CFB":
            case "OFB":
            case "GCM":
            case "XTS":
                requiresIV = true;
                break;
            default:
                throw new NoSuchAlgorithmException("Mode " + mode + " not supported");
        }
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equals("NOPADDING") && !padding.equals("PKCS5PADDING") && !padding.equals("PKCS7PADDING") 
            && !padding.equals("ZEROSPADDING") && !padding.equals("ISO7816PADDING") && !padding.equals("X923PADDING")) {
            throw new NoSuchPaddingException("Padding " + padding + " not supported");
        }
        this.padding = padding;
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        // For now, return a conservative estimate
        return inputLen + 16;
    }

    @Override
    protected byte[] engineGetIV() {
        return iv != null ? iv.clone() : null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKeySpec)) {
            throw new InvalidKeyException("Key must be a SecretKeySpec");
        }

        // Get the raw key bytes
        byte[] keyBytes = key.getEncoded();

        // XTS mode requires a 32-byte key (two 16-byte keys)
        if (mode.equals("XTS")) {
            if (keyBytes == null || keyBytes.length != 32) {
                throw new InvalidKeyException("XTS mode requires a 32-byte key (two 16-byte keys)");
            }
        } else {
            if (keyBytes == null || keyBytes.length != 16) {
                throw new InvalidKeyException("Key must be 16 bytes");
            }
        }
        this.key = keyBytes;

        if (params != null) {
            if (!(params instanceof IvParameterSpec)) {
                throw new InvalidAlgorithmParameterException("Parameters must be an IvParameterSpec");
            }
            this.iv = ((IvParameterSpec)params).getIV();
            if (this.iv.length != 16) {
                throw new InvalidAlgorithmParameterException("IV must be 16 bytes");
            }
        } else {
            this.iv = null;
        }

        // Check if we need an IV but don't have one
        if (requiresIV && this.iv == null) {
            throw new InvalidAlgorithmParameterException(mode + " mode requires an IV");
        }

        // Check if we have an IV but don't need one
        if (!requiresIV && this.iv != null) {
            throw new InvalidAlgorithmParameterException(mode + " mode cannot use IV");
        }

        this.opmode = opmode;
        try {
            int sm4Mode = (opmode == Cipher.ENCRYPT_MODE) ? SM4.MODE_ENCRYPT : SM4.MODE_DECRYPT;
            int sm4Algorithm = getSM4Algorithm();
            int paddingMode = getPaddingMode();
            // For stream cipher modes and authenticated encryption, always use PADDING_NONE
            if (sm4Algorithm == SM4.SM4_CTR || sm4Algorithm == SM4.SM4_CFB || 
                sm4Algorithm == SM4.SM4_OFB || sm4Algorithm == SM4.SM4_GCM || 
                sm4Algorithm == SM4.SM4_XTS) {
                paddingMode = SM4.PADDING_NONE;
            }
            
            // Initialize the SM4 cipher with appropriate padding
            sm4 = new SM4(sm4Algorithm, this.key, this.iv, sm4Mode, paddingMode);
            initialized = true;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SM4: " + e.getMessage());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            try {
                paramSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Cannot process algorithm parameters");
            }
        }
        engineInit(opmode, key, paramSpec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        try {
            if (opmode == Cipher.ENCRYPT_MODE) {
                return sm4.encryptUpdate(input, inputOffset, inputLen);
            } else {
                return sm4.decryptUpdate(input, inputOffset, inputLen);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error during update operation: " + e.getMessage());
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too small");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        try {
            // For stream cipher modes, we need to reinitialize for each operation
            boolean isStreamMode = (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || mode.equals("GCM"));
            if (isStreamMode) {
                int sm4Mode = (opmode == Cipher.ENCRYPT_MODE) ? SM4.MODE_ENCRYPT : SM4.MODE_DECRYPT;
                int sm4Algorithm = getSM4Algorithm();
                sm4 = new SM4(sm4Algorithm, this.key, this.iv, sm4Mode, SM4.PADDING_NONE);
            }

            byte[] result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                // First update with input if any
                if (input != null && inputLen > 0) {
                    result = sm4.encryptUpdate(input, inputOffset, inputLen);
                } else {
                    result = new byte[0];
                }
                
                // For XTS mode, we don't need a final block as it operates directly on blocks
                if (!mode.equals("XTS")) {
                    // Then get final block
                    byte[] finalBlock = sm4.encryptFinal();
                    
                    // Combine results if necessary
                    if (finalBlock != null && finalBlock.length > 0) {
                        byte[] combined = new byte[result.length + finalBlock.length];
                        System.arraycopy(result, 0, combined, 0, result.length);
                        System.arraycopy(finalBlock, 0, combined, result.length, finalBlock.length);
                        return combined;
                    }
                }
                return result;
            } else {
                // First update with input if any
                if (input != null && inputLen > 0) {
                    result = sm4.decryptUpdate(input, inputOffset, inputLen);
                } else {
                    result = new byte[0];
                }
                
                // For XTS mode, we don't need a final block as it operates directly on blocks
                if (!mode.equals("XTS")) {
                    // Then get final block
                    byte[] finalBlock = sm4.decryptFinal();
                    
                    // Combine results if necessary
                    if (finalBlock != null && finalBlock.length > 0) {
                        byte[] combined = new byte[result.length + finalBlock.length];
                        System.arraycopy(result, 0, combined, 0, result.length);
                        System.arraycopy(finalBlock, 0, combined, result.length, finalBlock.length);
                        return combined;
                    }
                }
                return result;
            }
        } catch (Exception e) {
            throw new BadPaddingException("Error during final operation: " + e.getMessage());
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too small");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    private int getSM4Algorithm() {
        switch (mode.toUpperCase()) {
            case "ECB":
                requiresIV = false;
                return SM4.SM4_ECB;
            case "CBC":
                requiresIV = true;
                return SM4.SM4_CBC;
            case "CTR":
                requiresIV = true;
                return SM4.SM4_CTR;
            case "CFB":
                requiresIV = true;
                return SM4.SM4_CFB;
            case "OFB":
                requiresIV = true;
                return SM4.SM4_OFB;
            case "GCM":
                requiresIV = true;
                return SM4.SM4_GCM;
            case "XTS":
                requiresIV = true;
                return SM4.SM4_XTS;
            default:
                throw new IllegalArgumentException("Unsupported mode: " + mode);
        }
    }

    private int getPaddingMode() {
        // Stream cipher modes (CTR, CFB, OFB) and authenticated encryption (GCM) don't use padding
        if (!padding.equalsIgnoreCase("NOPADDING") && 
            (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || 
             mode.equals("GCM") || mode.equals("XTS"))) {
            throw new IllegalArgumentException("Stream cipher modes and authenticated encryption must use NOPADDING");
        }

        switch (padding.toUpperCase()) {
            case "NOPADDING":
                return SM4.PADDING_NONE;
            case "ZEROSPADDING":
                return SM4.PADDING_ZEROS;
            case "ISO7816PADDING":
                return SM4.PADDING_ISO7816;
            case "X923PADDING":
                return SM4.PADDING_X923;
            case "PKCS5PADDING":
                return SM4.PADDING_PKCS5;
            case "PKCS7PADDING":
                return SM4.PADDING_PKCS7;
            default:
                throw new IllegalArgumentException("Unsupported padding mode: " + padding);
        }
    }
}
