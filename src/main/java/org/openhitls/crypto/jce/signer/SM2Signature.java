package org.openhitls.crypto.jce.signer;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import org.openhitls.crypto.core.asymmetric.SM2;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.key.SM2PrivateKey;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;

public class SM2Signature extends SignatureSpi {
    private SM2 sm2;
    private byte[] buffer;
    private boolean forSigning;
    private byte[] userId;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof SM2PublicKey)) {
            throw new InvalidKeyException("Key must be an instance of SM2PublicKey");
        }
        try {
            sm2 = new SM2(((SM2PublicKey)publicKey).getEncoded(), null);
            if (userId != null) {
                sm2.setUserId(userId);
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SM2", e);
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
        if (!(privateKey instanceof SM2PrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of SM2PrivateKey");
        }
        try {
            sm2 = new SM2(null, ((SM2PrivateKey)privateKey).getEncoded());
            if (userId != null) {
                sm2.setUserId(userId);
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SM2", e);
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
            return sm2.signData(buffer);
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
            return sm2.verifySignature(buffer, sigBytes);
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
        if (sm2 != null) {
            sm2.setUserId(userId);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }
}
