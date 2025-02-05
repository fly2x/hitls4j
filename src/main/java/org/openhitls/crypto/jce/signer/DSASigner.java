package org.openhitls.crypto.jce.signer;

import java.security.SignatureSpi;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import org.openhitls.crypto.core.asymmetric.DSAImpl;

public class DSASigner extends SignatureSpi {
    private DSAImpl dsa;
    private byte[] buffer;
    private int bufferOffset;
    private static final int BUFFER_SIZE = 8192;

    public DSASigner() {
        buffer = new byte[BUFFER_SIZE];
        bufferOffset = 0;
        dsa = new DSAImpl();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof DSAPublicKey)) {
            throw new InvalidKeyException("Key must be a DSAPublicKey");
        }
        DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
        
        try {
            // Create a new DSA instance for each verification operation
            dsa = new DSAImpl();
            
            // Set DSA parameters
            DSAParameterSpec params = new DSAParameterSpec(
                dsaKey.getParams().getP(),
                dsaKey.getParams().getQ(),
                dsaKey.getParams().getG()
            );
            
            // Set the parameters
            dsa.setParameters(params.getP().toByteArray(), params.getQ().toByteArray(), params.getG().toByteArray());
            
            // Convert public key to byte array
            byte[] y = dsaKey.getY().toByteArray();
            // Remove leading zero if present
            if (y[0] == 0) {
                byte[] tmp = new byte[y.length - 1];
                System.arraycopy(y, 1, tmp, 0, tmp.length);
                y = tmp;
            }
            
            // Set the public key
            dsa.setKeys(y, null);
            
            bufferOffset = 0;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize verification key", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof DSAPrivateKey)) {
            throw new InvalidKeyException("Key must be a DSAPrivateKey");
        }
        DSAPrivateKey dsaKey = (DSAPrivateKey) privateKey;
        
        try {
            // Create a new DSA instance for each signing operation
            dsa = new DSAImpl();
            
            // Set DSA parameters
            DSAParameterSpec params = new DSAParameterSpec(
                dsaKey.getParams().getP(),
                dsaKey.getParams().getQ(),
                dsaKey.getParams().getG()
            );
            
            // Set the parameters
            dsa.setParameters(params.getP().toByteArray(), params.getQ().toByteArray(), params.getG().toByteArray());
            
            // Convert private key to byte array
            byte[] x = dsaKey.getX().toByteArray();
            // Remove leading zero if present
            if (x[0] == 0) {
                byte[] tmp = new byte[x.length - 1];
                System.arraycopy(x, 1, tmp, 0, tmp.length);
                x = tmp;
            }
            
            // Set the private key
            dsa.setKeys(null, x);
            
            bufferOffset = 0;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize signing key", e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (bufferOffset >= BUFFER_SIZE) {
            throw new SignatureException("Buffer full");
        }
        buffer[bufferOffset++] = b;
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (len > (BUFFER_SIZE - bufferOffset)) {
            throw new SignatureException("Buffer overflow");
        }
        System.arraycopy(b, off, buffer, bufferOffset, len);
        bufferOffset += len;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            byte[] data = new byte[bufferOffset];
            System.arraycopy(buffer, 0, data, 0, bufferOffset);
            return dsa.sign(data);
        } catch (Exception e) {
            throw new SignatureException("Failed to generate signature", e);
        } finally {
            bufferOffset = 0;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            byte[] data = new byte[bufferOffset];
            System.arraycopy(buffer, 0, data, 0, bufferOffset);
            return dsa.verify(data, sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Failed to verify signature", e);
        } finally {
            bufferOffset = 0;
        }
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineGetParameter is not supported");
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("engineSetParameter is not supported");
    }
} 
