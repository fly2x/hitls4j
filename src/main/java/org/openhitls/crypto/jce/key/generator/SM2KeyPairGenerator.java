package org.openhitls.crypto.jce.key.generator;

import java.security.*;
import java.security.spec.*;
import org.openhitls.crypto.core.asymmetric.SM2;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.key.SM2PrivateKey;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;

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
        this.params = SM2ParameterSpec.getInstance();
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.random = random;
        
        if (params instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec)params).getName();
            if (!"sm2p256v1".equalsIgnoreCase(name)) {
                throw new InvalidAlgorithmParameterException("Only sm2p256v1 curve is supported");
            }
            this.params = SM2ParameterSpec.getInstance();
        } else if (params instanceof ECParameterSpec) {
            // Verify if the parameters match SM2 curve
            ECParameterSpec ecParams = (ECParameterSpec)params;
            ECParameterSpec sm2Params = SM2ParameterSpec.getInstance();
            
            if (!ecParams.getCurve().equals(sm2Params.getCurve()) ||
                !ecParams.getGenerator().equals(sm2Params.getGenerator()) ||
                !ecParams.getOrder().equals(sm2Params.getOrder()) ||
                ecParams.getCofactor() != sm2Params.getCofactor()) {
                throw new InvalidAlgorithmParameterException("Parameters must match SM2 curve");
            }
            this.params = ecParams;
        } else {
            throw new InvalidAlgorithmParameterException("Only ECGenParameterSpec and ECParameterSpec are supported");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        SM2 sm2 = new SM2();
        byte[] publicKey = sm2.getPublicKey();
        byte[] privateKey = sm2.getPrivateKey();
        
        return new KeyPair(
            new SM2PublicKey(publicKey),
            new SM2PrivateKey(privateKey)
        );
    }
}
