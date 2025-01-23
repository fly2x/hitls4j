package org.openhitls.crypto.jce.key.factory;

import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.Arrays;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.key.ECPublicKey;

public class ECKeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            return new ECPublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPublicKeySpec) {
            ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
            ECParameterSpec params = ecSpec.getParams();
            
            return new ECPublicKey(ecSpec.getW(), params);
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + 
            keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return new ECPrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
            ECParameterSpec params = ecSpec.getParams();
            
            return new ECPrivateKey(ecSpec.getS(), params);
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + 
            keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {
        if (key instanceof ECPublicKey) {
            ECPublicKey sm2Key = (ECPublicKey)key;
            
            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            
            if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                byte[] encoded = sm2Key.getEncoded();
                
                if (encoded[0] != 0x04) {
                    throw new InvalidKeySpecException("Invalid SM2 public key encoding");
                }
                
                int fieldSize = (encoded.length - 1) / 2;
                
                byte[] x = Arrays.copyOfRange(encoded, 1, 1 + fieldSize);
                byte[] y = Arrays.copyOfRange(encoded, 1 + fieldSize, encoded.length);
                
                ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
                
                ECParameterSpec params = sm2Key.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                
                return keySpec.cast(new ECPublicKeySpec(w, params));
            }
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey sm2Key = (ECPrivateKey)key;
            
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            
            if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                byte[] encoded = sm2Key.getEncoded();
                
                BigInteger s = new BigInteger(1, encoded);
                
                ECParameterSpec params = sm2Key.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                
                return keySpec.cast(new ECPrivateKeySpec(s, params));
            }
        }
        
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof ECPublicKey || key instanceof ECPrivateKey) {
            return key;
        }
        
        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}
