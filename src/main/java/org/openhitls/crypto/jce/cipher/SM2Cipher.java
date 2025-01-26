package org.openhitls.crypto.jce.cipher;

import javax.crypto.CipherSpi;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import org.openhitls.crypto.core.asymmetric.ECDSAImpl;
import org.openhitls.crypto.jce.key.ECPublicKey;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

public class SM2Cipher extends CipherSpi {
    private ECDSAImpl ecdsaImpl;
    private int opmode;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("SM2 only supports ECB mode");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NOPADDING".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0; // SM2 is not a block cipher
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen; // This is an approximation
    }

    @Override
    protected byte[] engineGetIV() {
        return null; // SM2 doesn't use IV
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null; // SM2 doesn't use parameters
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            this.opmode = opmode;  // Store the operation mode first
            if (opmode == Cipher.ENCRYPT_MODE) {
                if (!(key instanceof ECPublicKey)) {
                    throw new InvalidKeyException("Public key required for encryption");
                }
                ECParameterSpec params = ((ECPublicKey)key).getParams();
                if (!(params instanceof ECNamedCurveSpec)) {
                    throw new InvalidKeyException("Key parameters must be an instance of ECNamedCurveSpec");
                }
                String curveName = ((ECNamedCurveSpec)params).getName();
                ecdsaImpl = new ECDSAImpl(curveName, ((ECPublicKey)key).getEncoded(), null);
            } else if (opmode == Cipher.DECRYPT_MODE) {
                if (!(key instanceof ECPrivateKey)) {
                    throw new InvalidKeyException("Private key required for decryption");
                }
                ECParameterSpec params = ((ECPrivateKey)key).getParams();
                if (!(params instanceof ECNamedCurveSpec)) {
                    throw new InvalidKeyException("Key parameters must be an instance of ECNamedCurveSpec");
                }
                String curveName = ((ECNamedCurveSpec)params).getName();
                ecdsaImpl = new ECDSAImpl(curveName, null, ((ECPrivateKey)key).getEncoded());
            } else {
                throw new InvalidKeyException("Unsupported operation mode");
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SM2", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Ignore params as SM2 doesn't use them
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new UnsupportedOperationException("SM2 does not support partial updates");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        throw new UnsupportedOperationException("SM2 does not support partial updates");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[] data = new byte[inputLen];
        System.arraycopy(input, inputOffset, data, 0, inputLen);

        try {
            if (opmode == Cipher.ENCRYPT_MODE) {
                return ecdsaImpl.encryptData(data);
            } else {
                return ecdsaImpl.decryptData(data);
            }
        } catch (Exception e) {
            throw new BadPaddingException("Operation failed: " + e.getMessage());
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }
}
