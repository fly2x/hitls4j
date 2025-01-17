package org.openhitls.crypto.jce.key.generator;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM4KeyGenerator extends KeyGeneratorSpi {
    private SecureRandom random;
    private int keySize = 128; // SM4 uses 128-bit keys

    public SM4KeyGenerator() {
        super();
    }

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("SM4 key generation does not use any parameters");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != 128) {
            throw new IllegalArgumentException("SM4 only supports 128-bit keys");
        }
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (random == null) {
            random = new SecureRandom();
        }

        byte[] keyBytes = new byte[keySize / 8];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "SM4");
    }
}
