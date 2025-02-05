package org.openhitls.crypto.jce.key;

import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;
import java.math.BigInteger;

public class DSAPrivateKeyImpl implements DSAPrivateKey {
    private static final long serialVersionUID = 1L;
    private final DSAParameterSpec params;
    private final BigInteger x; // private key value

    public DSAPrivateKeyImpl(DSAParameterSpec params, byte[] xBytes) {
        this.params = params;
        this.x = new BigInteger(1, xBytes); // Use 1 as signum for positive value
    }

    @Override
    public BigInteger getX() {
        return x;
    }

    @Override
    public DSAParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        // For now, return null as we don't need ASN.1 encoding for our tests
        return null;
    }
} 