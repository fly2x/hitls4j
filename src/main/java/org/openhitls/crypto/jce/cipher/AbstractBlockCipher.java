package org.openhitls.crypto.jce.cipher;

import org.openhitls.crypto.core.symmetric.SymmetricCipherImpl;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public abstract class AbstractBlockCipher extends CipherSpi {
    protected SymmetricCipherImpl symmetricCipher;
    protected int opmode;
    protected byte[] key;
    protected byte[] iv;
    protected String mode;
    protected String padding = "NOPADDING";
    protected boolean initialized = false;
    protected boolean requiresIV;

    public abstract String getAlgorithmName();
    public abstract void validateKeySize(byte[] keyBytes) throws InvalidKeyException;
    public abstract String[] getSupportedModes();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        mode = mode.toUpperCase();
        if (!Arrays.asList(getSupportedModes()).contains(mode)) {
            throw new NoSuchAlgorithmException("Mode " + mode + " not supported");
        }
        
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
        int blockSize = engineGetBlockSize();

        // For stream cipher modes (CTR, CFB, OFB) and GCM mode, output size equals input size
        if (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || mode.equals("GCM")) {
            return inputLen;
        }

        // For block cipher modes (ECB, CBC)
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (padding.equals("NOPADDING")) {
                // For NoPadding, input must be multiple of block size
                if (inputLen % blockSize != 0) {
                    throw new IllegalArgumentException("Input length must be multiple of " + blockSize + " for NoPadding");
                }
                return inputLen;
            } else {
                // For padded modes, output will be rounded up to next block size
                // Example: if input is 20 bytes and block size is 16:
                // Need to pad to next multiple of 16, so 32 bytes
                return ((inputLen + blockSize) / blockSize) * blockSize;
            }
        } else { // Cipher.DECRYPT_MODE
            if (padding.equals("NOPADDING")) {
                // For NoPadding, output size equals input size
                if (inputLen % blockSize != 0) {
                    throw new IllegalArgumentException("Input length must be multiple of " + blockSize + " for NoPadding");
                }
                return inputLen;
            } else {
                // For padded modes, output will be at most input size
                // (could be less due to padding removal)
                if (inputLen % blockSize != 0) {
                    throw new IllegalArgumentException("Input length must be multiple of " + blockSize + " for decryption");
                }
                return inputLen;
            }
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return iv != null ? iv.clone() : null;
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
        validateKeySize(keyBytes);
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
            int sm4Mode = (opmode == Cipher.ENCRYPT_MODE) ? SymmetricCipherImpl.MODE_ENCRYPT : SymmetricCipherImpl.MODE_DECRYPT;
            int paddingMode = getPaddingMode();
            // Initialize the SM4 cipher with appropriate padding
            symmetricCipher = new SymmetricCipherImpl(getAlgorithmName(), mode, this.key, this.iv, sm4Mode, paddingMode);
            initialized = true;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize cipher: " + e.getMessage());
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
            return symmetricCipher.update(input, inputOffset, inputLen);
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

        // For NoPadding mode, validate input length is multiple of block size
        if ("NOPADDING".equalsIgnoreCase(padding) && ("CBC".equals(mode) || "ECB".equals(mode))) {
            if (inputLen % engineGetBlockSize() != 0) {
                throw new IllegalBlockSizeException("Input length must be multiple of " + engineGetBlockSize() + " when using NoPadding");
            }
        }

        try {
            // For stream cipher modes, we need to reinitialize for each operation
            boolean isStreamMode = (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || mode.equals("GCM"));
            if (isStreamMode) {
                int sm4Mode = (opmode == Cipher.ENCRYPT_MODE) ? SymmetricCipherImpl.MODE_ENCRYPT : SymmetricCipherImpl.MODE_DECRYPT;
                symmetricCipher = new SymmetricCipherImpl(getAlgorithmName(), mode, this.key, this.iv, sm4Mode, SymmetricCipherImpl.PADDING_NONE);
            }

            byte[] result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                // First update with input if any
                if (input != null && inputLen > 0) {
                    result = symmetricCipher.update(input, inputOffset, inputLen);
                } else {
                    result = new byte[0];
                }
                
                // For XTS mode, we don't need a final block as it operates directly on blocks
                if (!mode.equals("XTS")) {
                    // Then get final block
                    byte[] finalBlock = symmetricCipher.doFinal();
                    
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
                    result = symmetricCipher.update(input, inputOffset, inputLen);
                } else {
                    result = new byte[0];
                }
                
                // For XTS mode, we don't need a final block as it operates directly on blocks
                if (!mode.equals("XTS")) {
                    // Then get final block
                    byte[] finalBlock = symmetricCipher.doFinal();
                    
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

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (iv != null) {
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance(getAlgorithmName());
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    protected int getPaddingMode() {
        // Stream cipher modes (CTR, CFB, OFB) and authenticated encryption (GCM) don't use padding
        if (!padding.equalsIgnoreCase("NOPADDING") && 
            (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || 
             mode.equals("GCM") || mode.equals("XTS"))) {
            throw new IllegalArgumentException("Stream cipher modes and authenticated encryption must use NOPADDING");
        }
        switch (padding.toUpperCase()) {
            case "NOPADDING":
                return SymmetricCipherImpl.PADDING_NONE;
            case "ZEROSPADDING":
                return SymmetricCipherImpl.PADDING_ZEROS;
            case "ISO7816PADDING":
                return SymmetricCipherImpl.PADDING_ISO7816;
            case "X923PADDING":
                return SymmetricCipherImpl.PADDING_X923;
            case "PKCS5PADDING":
                return SymmetricCipherImpl.PADDING_PKCS5;
            case "PKCS7PADDING":
                return SymmetricCipherImpl.PADDING_PKCS7;
            default:
                throw new IllegalArgumentException("Unsupported padding mode: " + padding);
        }
    }
} 