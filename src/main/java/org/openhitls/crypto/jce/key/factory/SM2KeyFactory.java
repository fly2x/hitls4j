package org.openhitls.crypto.jce.key.factory;

import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.Arrays;
import org.openhitls.crypto.jce.key.SM2PrivateKey;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class SM2KeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            return new SM2PublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPublicKeySpec) {
            ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
            ECParameterSpec params = ecSpec.getParams();
            
            try {
                // Get standard SM2 parameters for comparison
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
                ECParameterSpec sm2Params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
                
                // Verify if the parameters match SM2 curve
                if (!params.getCurve().equals(sm2Params.getCurve()) ||
                    !params.getGenerator().equals(sm2Params.getGenerator())) {
                    throw new InvalidKeySpecException("Parameters must match SM2 curve");
                }
            } catch (Exception e) {
                throw new InvalidKeySpecException("Failed to verify SM2 parameters: " + e.getMessage());
            }
            
            return new SM2PublicKey(ecSpec.getW(), params);
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + 
            keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return new SM2PrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
            ECParameterSpec params = ecSpec.getParams();
            
            try {
                // Get standard SM2 parameters for comparison
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
                ECParameterSpec sm2Params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
                
                // Verify if the parameters match SM2 curve
                if (!params.getCurve().equals(sm2Params.getCurve()) ||
                    !params.getGenerator().equals(sm2Params.getGenerator())) {
                    throw new InvalidKeySpecException("Parameters must match SM2 curve");
                }
            } catch (Exception e) {
                throw new InvalidKeySpecException("Failed to verify SM2 parameters: " + e.getMessage());
            }
            
            return new SM2PrivateKey(ecSpec.getS(), params);
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + 
            keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {
        if (key instanceof SM2PublicKey) {
            SM2PublicKey sm2Key = (SM2PublicKey)key;
            
            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            
            if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                if (encoded[0] != 0x04 || encoded.length != 65) {
                    throw new InvalidKeySpecException("Invalid SM2 public key encoding");
                }
                
                // Extract X and Y coordinates
                byte[] xBytes = Arrays.copyOfRange(encoded, 1, 33);
                byte[] yBytes = Arrays.copyOfRange(encoded, 33, 65);
                
                BigInteger x = new BigInteger(1, xBytes);
                BigInteger y = new BigInteger(1, yBytes);
                ECPoint w = new ECPoint(x, y);
                
                ECParameterSpec params = sm2Key.getParams();
                if (params == null) {
                    // If params not stored in key, get default SM2 params
                    try {
                        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                        algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
                        params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
                    } catch (Exception e) {
                        throw new InvalidKeySpecException("Failed to get SM2 parameters: " + e.getMessage());
                    }
                }
                
                return keySpec.cast(new ECPublicKeySpec(w, params));
            }
        } else if (key instanceof SM2PrivateKey) {
            SM2PrivateKey sm2Key = (SM2PrivateKey)key;
            
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            
            if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                BigInteger s = new BigInteger(1, encoded);
                
                ECParameterSpec params = sm2Key.getParams();
                if (params == null) {
                    // If params not stored in key, get default SM2 params
                    try {
                        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                        algorithmParameters.init(new ECGenParameterSpec("sm2p256v1"));
                        params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
                    } catch (Exception e) {
                        throw new InvalidKeySpecException("Failed to get SM2 parameters: " + e.getMessage());
                    }
                }
                
                return keySpec.cast(new ECPrivateKeySpec(s, params));
            }
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof SM2PublicKey || key instanceof SM2PrivateKey) {
            return key;
        }
        
        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}
