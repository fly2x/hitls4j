package org.openhitls.crypto.jce.key;

import java.security.PublicKey;
import java.security.spec.*;
import java.util.Arrays;

public class SM2PublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;
    private final byte[] keyBytes;
    private final ECParameterSpec params;

    public SM2PublicKey(byte[] keyBytes) {
        this.keyBytes = keyBytes.clone();
        this.params = null;
    }

    public SM2PublicKey(byte[] keyBytes, ECParameterSpec params) {
        this.keyBytes = keyBytes.clone();
        this.params = params;
    }

    public SM2PublicKey(ECPoint w, ECParameterSpec params) {
        // Convert ECPoint to SM2PublicKey format
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
        System.arraycopy(x, 0, encoded, 1, 32);
        
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
        System.arraycopy(y, 0, encoded, 33, 32);
        
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
        SM2PublicKey that = (SM2PublicKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }
}
