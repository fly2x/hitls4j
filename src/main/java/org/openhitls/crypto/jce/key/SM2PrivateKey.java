package org.openhitls.crypto.jce.key;

import java.security.PrivateKey;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.Arrays;

public class SM2PrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;
    private final byte[] keyBytes;
    private final ECParameterSpec params;

    public SM2PrivateKey(byte[] keyBytes) {
        this.keyBytes = keyBytes.clone();
        this.params = null;
    }

    public SM2PrivateKey(byte[] keyBytes, ECParameterSpec params) {
        this.keyBytes = keyBytes.clone();
        this.params = params;
    }

    public SM2PrivateKey(BigInteger s, ECParameterSpec params) {
        // Convert private key to 32 bytes, big-endian
        byte[] encoded = new byte[32];
        byte[] sBytes = s.toByteArray();
        if (sBytes.length > 32) {
            // Remove leading zeros if present
            sBytes = Arrays.copyOfRange(sBytes, sBytes.length - 32, sBytes.length);
        } else if (sBytes.length < 32) {
            // Pad with zeros if needed
            byte[] padded = new byte[32];
            System.arraycopy(sBytes, 0, padded, 32 - sBytes.length, sBytes.length);
            sBytes = padded;
        }
        System.arraycopy(sBytes, 0, encoded, 0, 32);
        
        this.keyBytes = encoded;
        this.params = params;
    }

    public ECParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
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
        SM2PrivateKey that = (SM2PrivateKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }
}
