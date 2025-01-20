package org.openhitls.crypto.jce.key.factory;

import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.Arrays;
import org.openhitls.crypto.jce.key.SM2PrivateKey;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;

public class SM2KeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            return new SM2PublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPublicKeySpec) {
            ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
            ECParameterSpec params = ecSpec.getParams();
            ECParameterSpec sm2Params = SM2ParameterSpec.getInstance();
            
            // Verify if the parameters match SM2 curve
            if (!params.getCurve().equals(sm2Params.getCurve()) ||
                !params.getGenerator().equals(sm2Params.getGenerator()) ||
                !params.getOrder().equals(sm2Params.getOrder()) ||
                params.getCofactor() != sm2Params.getCofactor()) {
                throw new InvalidKeySpecException("Parameters must match SM2 curve");
            }
            
            // Convert ECPoint to SM2PublicKey format
            ECPoint w = ecSpec.getW();
            byte[] encoded = new byte[65];
            encoded[0] = 0x04; // uncompressed point
            
            // Convert X coordinate to 32 bytes, big-endian
            byte[] x = w.getAffineX().toByteArray();
            if (x.length > 32) {
                // Remove leading zeros if present
                x = Arrays.copyOfRange(x, x.length - 32, x.length);
            } else if (x.length < 32) {
                // Pad with zeros if needed
                byte[] padded = new byte[32];
                System.arraycopy(x, 0, padded, 32 - x.length, x.length);
                x = padded;
            }
            
            // Convert Y coordinate to 32 bytes, big-endian
            byte[] y = w.getAffineY().toByteArray();
            if (y.length > 32) {
                // Remove leading zeros if present
                y = Arrays.copyOfRange(y, y.length - 32, y.length);
            } else if (y.length < 32) {
                // Pad with zeros if needed
                byte[] padded = new byte[32];
                System.arraycopy(y, 0, padded, 32 - y.length, y.length);
                y = padded;
            }
            
            System.arraycopy(x, 0, encoded, 1, 32);
            System.arraycopy(y, 0, encoded, 33, 32);
            
            return new SM2PublicKey(encoded);
        }
        throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return new SM2PrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
            ECParameterSpec params = ecSpec.getParams();
            ECParameterSpec sm2Params = SM2ParameterSpec.getInstance();
            
            // Verify if the parameters match SM2 curve
            if (!params.getCurve().equals(sm2Params.getCurve()) ||
                !params.getGenerator().equals(sm2Params.getGenerator()) ||
                !params.getOrder().equals(sm2Params.getOrder()) ||
                params.getCofactor() != sm2Params.getCofactor()) {
                throw new InvalidKeySpecException("Parameters must match SM2 curve");
            }
            
            // Convert BigInteger to SM2PrivateKey format
            byte[] s = ecSpec.getS().toByteArray();
            byte[] encoded = new byte[32];
            
            if (s.length > 32) {
                // Remove leading zeros if present
                System.arraycopy(s, s.length - 32, encoded, 0, 32);
            } else {
                // Pad with zeros if needed
                System.arraycopy(s, 0, encoded, 32 - s.length, s.length);
            }
            
            return new SM2PrivateKey(encoded);
        }
        throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) 
            throws InvalidKeySpecException {
        if (key instanceof SM2PublicKey) {
            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                if (encoded[0] != 0x04 || encoded.length != 65) {
                    throw new InvalidKeySpecException("Invalid SM2 public key encoding");
                }
                
                byte[] xBytes = Arrays.copyOfRange(encoded, 1, 33);
                byte[] yBytes = Arrays.copyOfRange(encoded, 33, 65);
                
                BigInteger x = new BigInteger(1, xBytes);
                BigInteger y = new BigInteger(1, yBytes);
                ECPoint w = new ECPoint(x, y);
                
                return keySpec.cast(new ECPublicKeySpec(w, SM2ParameterSpec.getInstance()));
            }
        } else if (key instanceof SM2PrivateKey) {
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            } else if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                BigInteger s = new BigInteger(1, encoded);
                
                return keySpec.cast(new ECPrivateKeySpec(s, SM2ParameterSpec.getInstance()));
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
