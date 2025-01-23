package org.openhitls.crypto.jce.cipher;

import org.openhitls.crypto.core.symmetric.AES;
import org.openhitls.crypto.exception.CryptoException;

import javax.crypto.CipherSpi;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class HiTlsAES extends CipherSpi {
    private AES aes;
    private boolean initialized = false;
    private int mode;
    private byte[] iv;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode == null) {
            throw new NoSuchAlgorithmException("null mode");
        }

        switch (mode.toUpperCase()) {
            case "ECB":
                this.mode = AES.MODE_ECB;
                break;
            case "CBC":
                this.mode = AES.MODE_CBC;
                break;
            case "CTR":
                this.mode = AES.MODE_CTR;
                break;
            case "GCM":
                this.mode = AES.MODE_GCM;
                break;
            case "CFB":
                this.mode = AES.MODE_CFB;
                break;
            case "OFB":
                this.mode = AES.MODE_OFB;
                break;
            default:
                throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("Unsupported padding: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 16; // AES block size is always 16 bytes
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen; // AES operates on exact block sizes, padding handled at higher level
    }

    @Override
    protected byte[] engineGetIV() {
        return iv != null ? iv.clone() : null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;  // TODO: Implement if needed
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        // For modes requiring IV, generate a random IV
        byte[] generatedIv = null;
        if (mode != AES.MODE_ECB) {
            generatedIv = new byte[16];  // AES block size
            random.nextBytes(generatedIv);
        }
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec)(generatedIv != null ? new IvParameterSpec(generatedIv) : null), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Failed to initialize cipher", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            IvParameterSpec ivSpec = null;
            if (params != null) {
                ivSpec = params.getParameterSpec(IvParameterSpec.class);
            }
            engineInit(opmode, key, ivSpec, random);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException("Invalid parameter spec", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey");
        }

        // Handle IV parameter
        byte[] ivBytes = null;
        if (params != null) {
            if (!(params instanceof IvParameterSpec)) {
                throw new InvalidAlgorithmParameterException("Only IvParameterSpec is supported");
            }
            ivBytes = ((IvParameterSpec) params).getIV();
            if (ivBytes == null || ivBytes.length != 16) {  // AES block size
                throw new InvalidAlgorithmParameterException("Invalid IV length");
            }
        } else if (mode != AES.MODE_ECB) {
            throw new InvalidAlgorithmParameterException("IV parameter required for " + 
                (mode == AES.MODE_CBC ? "CBC" : 
                 mode == AES.MODE_CTR ? "CTR" : "GCM") + " mode");
        }

        this.iv = ivBytes != null ? ivBytes.clone() : null;

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        try {
            int aesOpMode = (opmode == Cipher.ENCRYPT_MODE) ? AES.MODE_ENCRYPT : AES.MODE_DECRYPT;
            aes = new AES(mode, keyBytes.length * 8, keyBytes, iv, aesOpMode);
            initialized = true;
        } catch (CryptoException e) {
            throw new InvalidKeyException("Failed to initialize AES", e);
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        try {
            byte[] output = new byte[inputLen];
            aes.update(input, inputOffset, inputLen, output, 0);
            return output;
        } catch (CryptoException e) {
            throw new RuntimeException("Failed to process data", e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                             byte[] output, int outputOffset)
            throws ShortBufferException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (output == null) {
            throw new IllegalArgumentException("Output buffer cannot be null");
        }

        if (outputOffset < 0) {
            throw new IllegalArgumentException("Output offset cannot be negative");
        }

        if (output.length - outputOffset < inputLen) {
            throw new ShortBufferException("Output buffer too small");
        }

        try {
            aes.update(input, inputOffset, inputLen, output, outputOffset);
            return inputLen;
        } catch (CryptoException e) {
            throw new RuntimeException("Failed to process data", e);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        try {
            byte[] output = null;
            if (input != null && inputLen > 0) {
                output = new byte[inputLen];
                aes.update(input, inputOffset, inputLen, output, 0);
            }
            byte[] finalBlock = aes.doFinal();
            if (output == null) {
                return finalBlock;
            }
            if (finalBlock.length > 0) {
                byte[] result = new byte[output.length + finalBlock.length];
                System.arraycopy(output, 0, result, 0, output.length);
                System.arraycopy(finalBlock, 0, result, output.length, finalBlock.length);
                return result;
            }
            return output;
        } catch (CryptoException e) {
            throw new RuntimeException("Failed to process data", e);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                              byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        try {
            int totalSize = 0;
            if (input != null && inputLen > 0) {
                if (output.length - outputOffset < inputLen) {
                    throw new ShortBufferException("Output buffer too small");
                }
                aes.update(input, inputOffset, inputLen, output, outputOffset);
                totalSize = inputLen;
                outputOffset += inputLen;
            }
            byte[] finalBlock = aes.doFinal();
            if (finalBlock.length > 0) {
                if (output.length - outputOffset < finalBlock.length) {
                    throw new ShortBufferException("Output buffer too small for final block");
                }
                System.arraycopy(finalBlock, 0, output, outputOffset, finalBlock.length);
                totalSize += finalBlock.length;
            }
            return totalSize;
        } catch (CryptoException e) {
            throw new RuntimeException("Failed to process data", e);
        }
    }
}
