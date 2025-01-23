package org.openhitls.crypto.jce.key;

import java.security.spec.*;
import java.math.BigInteger;
import java.util.Arrays;

public class ECPrivateKey implements java.security.interfaces.ECPrivateKey {
    private static final long serialVersionUID = 1L;
    private final byte[] keyBytes;
    private final ECParameterSpec params;
    private BigInteger s;  // Cache the private value to avoid repeated computation

    public ECPrivateKey(byte[] keyBytes) {
        this.keyBytes = keyBytes.clone();
        this.params = null;
        this.s = null;
    }

    public ECPrivateKey(byte[] keyBytes, ECParameterSpec params) {
        this.keyBytes = keyBytes.clone();
        this.params = params;
        this.s = null;
    }

    public ECPrivateKey(BigInteger s, ECParameterSpec params) {
        this.s = s;
        // Get field size in bytes
        int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
        byte[] encoded = new byte[fieldSize];
        byte[] sBytes = s.toByteArray();
        if (sBytes.length > fieldSize) {
            // Remove leading zeros if present
            sBytes = Arrays.copyOfRange(sBytes, sBytes.length - fieldSize, sBytes.length);
        } else if (sBytes.length < fieldSize) {
            // Pad with zeros if needed
            byte[] padded = new byte[fieldSize];
            System.arraycopy(sBytes, 0, padded, fieldSize - sBytes.length, sBytes.length);
            sBytes = padded;
        }
        System.arraycopy(sBytes, 0, encoded, 0, fieldSize);
        
        this.keyBytes = encoded;
        this.params = params;
    }

    public ECParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return keyBytes.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECPrivateKey that = (ECPrivateKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }

    @Override
    public BigInteger getS() {
        if (s == null && keyBytes != null) {
            s = new BigInteger(1, keyBytes);
        }
        return s;
    }
}
