package org.openhitls.crypto.jce.key.factory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.openhitls.crypto.jce.key.SM2PrivateKey;
import org.openhitls.crypto.jce.key.SM2PublicKey;

public class SM2KeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            return new SM2PublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
        }
        throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return new SM2PrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());
        }
        throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) 
            throws InvalidKeySpecException {
        if (key instanceof SM2PublicKey) {
            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
        } else if (key instanceof SM2PrivateKey) {
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
        }
        throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof SM2PublicKey || key instanceof SM2PrivateKey) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}
