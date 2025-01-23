package org.openhitls.crypto.jce.key.generator;

import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import org.openhitls.crypto.core.asymmetric.SM2;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.key.SM2PrivateKey;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {
    private SecureRandom random;
    private ECParameterSpec params;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.random = random;
        // For SM2, keysize is always 256 bits
        if (keysize != 256) {
            throw new InvalidParameterException("SM2 key size must be 256 bits");
        }
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
            params.init(new ECGenParameterSpec("sm2p256v1"));
            this.params = params.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new InvalidParameterException("Failed to initialize SM2 parameters: " + e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.random = random;

        if (params == null) {
            try {
                // Use standard EC parameters for SM2 curve
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
                this.params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Failed to initialize SM2 parameters: " + e.getMessage());
            }
        } else if (params instanceof ECParameterSpec) {
            // Verify if the parameters match SM2 curve
            ECParameterSpec ecParams = (ECParameterSpec)params;
            try {
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
                ECParameterSpec sm2Params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            
                if (!ecParams.getCurve().equals(sm2Params.getCurve()) ||
                    !ecParams.getGenerator().equals(sm2Params.getGenerator())) {
                    throw new InvalidAlgorithmParameterException("Parameters must match SM2 curve");
                }
                this.params = ecParams;
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Failed to verify SM2 parameters: " + e.getMessage());
            }
        } else if (params instanceof ECGenParameterSpec) {
            ECGenParameterSpec spec = (ECGenParameterSpec)params;
            if (!"sm2p256v1".equalsIgnoreCase(spec.getName())) {
                throw new InvalidAlgorithmParameterException("Only sm2p256v1 curve is supported");
            }
            try {
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(spec);
                this.params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Failed to initialize SM2 parameters: " + e.getMessage());
            }
        } else {
            throw new InvalidAlgorithmParameterException("Only ECParameterSpec and ECGenParameterSpec are supported");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (random == null) {
            random = new SecureRandom();
        }

        try {
            SM2 sm2 = new SM2();
            byte[] publicKey = sm2.getPublicKey();
            byte[] privateKey = sm2.getPrivateKey();
            
            return new KeyPair(
                new SM2PublicKey(publicKey, params),
                new SM2PrivateKey(privateKey, params)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate SM2 key pair: " + e.getMessage());
        }
    }
}
