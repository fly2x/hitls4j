package org.openhitls.crypto.jce.signer;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import org.openhitls.crypto.core.asymmetric.ECDSAImpl;
import org.openhitls.crypto.jce.key.ECPublicKey;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;
import org.openhitls.crypto.core.CryptoConstants;

public class ECDSASigner extends SignatureSpi {
    private ECDSAImpl ecdsaImpl;
    private byte[] buffer;
    private boolean forSigning;
    private byte[] userId;
    private final int algorithm;

    public ECDSASigner(String algorithmName) {
        this.algorithm = getHashAlgorithm(algorithmName);
    }

    // Inner classes for different signature algorithms
    public static final class SHA256withECDSA extends ECDSASigner {
        public SHA256withECDSA() {
            super("SHA256");
        }
    }

    public static final class SHA384withECDSA extends ECDSASigner {
        public SHA384withECDSA() {
            super("SHA384");
        }
    }

    public static final class SHA512withECDSA extends ECDSASigner {
        public SHA512withECDSA() {
            super("SHA512");
        }
    }

    public static final class SM3withSM2 extends ECDSASigner {
        public SM3withSM2() {
            super("SM3");
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Key must be an instance of ECDSAPublicKey");
        }
        try {
            ECParameterSpec params = ((ECPublicKey)publicKey).getParams();
            if (!(params instanceof ECNamedCurveSpec)) {
                throw new InvalidKeyException("Key parameters must be an instance of ECNamedCurveSpec");
            }
            String curveName = ((ECNamedCurveSpec)params).getName();
            ecdsaImpl = new ECDSAImpl(curveName, algorithm, ((ECPublicKey)publicKey).getEncoded(), null);
            if (userId != null) {
                ecdsaImpl.setUserId(userId);
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize ECDSA", e);
        }
        buffer = null;
        forSigning = false;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) 
            throws InvalidKeyException {
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of ECDSAPrivateKey");
        }
        try {
            ECParameterSpec params = ((ECPrivateKey)privateKey).getParams();
            if (!(params instanceof ECNamedCurveSpec)) {
                throw new InvalidKeyException("Key parameters must be an instance of ECNamedCurveSpec");
            }
            String curveName = ((ECNamedCurveSpec)params).getName();
            ecdsaImpl = new ECDSAImpl(curveName, algorithm, null, ((ECPrivateKey)privateKey).getEncoded());
            if (userId != null) {
                ecdsaImpl.setUserId(userId);
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize ECDSA", e);
        }
        buffer = null;
        forSigning = true;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (buffer == null) {
            buffer = new byte[len];
            System.arraycopy(b, off, buffer, 0, len);
        } else {
            byte[] newBuffer = new byte[buffer.length + len];
            System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
            System.arraycopy(b, off, newBuffer, buffer.length, len);
            buffer = newBuffer;
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!forSigning) {
            throw new SignatureException("Not initialized for signing");
        }
        if (buffer == null) {
            throw new SignatureException("No data to sign");
        }
        try {
            return ecdsaImpl.signData(buffer);
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (forSigning) {
            throw new SignatureException("Not initialized for verification");
        }
        if (buffer == null) {
            throw new SignatureException("No data to verify");
        }
        try {
            return ecdsaImpl.verifySignature(buffer, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Verification failed", e);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) 
            throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override
    protected Object engineGetParameter(String param) 
            throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            userId = null;
            return;
        }
        if (!(params instanceof SM2ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only SM2ParameterSpec is supported");
        }
        userId = ((SM2ParameterSpec)params).getId().clone();
        if (ecdsaImpl != null) {
            ecdsaImpl.setUserId(userId);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private int getHashAlgorithm(String algorithmName) {
        switch (algorithmName) {
            case "SM3":
                return CryptoConstants.HASH_ALG_SM3;
            case "SHA256":
                return CryptoConstants.HASH_ALG_SHA256;
            case "SHA384":
                return CryptoConstants.HASH_ALG_SHA384;
            case "SHA512":
                return CryptoConstants.HASH_ALG_SHA512;
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithmName);
        }
    }
}
