package org.openhitls.crypto.jce.key;

import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.math.BigInteger;

public class DSAPublicKeyImpl implements DSAPublicKey {
    private static final long serialVersionUID = 1L;
    private final DSAParameterSpec params;
    private final BigInteger y; // public key value

    public DSAPublicKeyImpl(DSAParameterSpec params, byte[] yBytes) {
        this.params = params;
        this.y = new BigInteger(1, yBytes); // Use 1 as signum for positive value
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public DSAParams getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        // For now, return null as we don't need ASN.1 encoding for our tests
        return null;
    }
} 
