package org.openhitls.crypto.jce.key;

import java.security.spec.*;
import java.util.Arrays;
import java.math.BigInteger;

import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

public class ECPublicKey implements java.security.interfaces.ECPublicKey {
    private static final long serialVersionUID = 1L;
    private final byte[] keyBytes;
    private final ECParameterSpec params;
    private ECPoint w;  // Cache the ECPoint to avoid repeated computation

    public ECPublicKey(byte[] keyBytes) {
        this.keyBytes = keyBytes.clone();
        this.params = null;
        this.w = null;
    }

    public ECPublicKey(byte[] keyBytes, ECParameterSpec params) {
        this.keyBytes = keyBytes.clone();
        this.params = params;
        this.w = null;
    }

    public ECPublicKey(ECPoint w, ECParameterSpec params) {
        this.w = w;
        // Get field size in bytes
        int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
        byte[] encoded = new byte[1 + 2 * fieldSize]; // Format: 0x04 || X || Y
        encoded[0] = 0x04; // uncompressed point
        
        // Convert X coordinate to fieldSize bytes, big-endian
        byte[] x = w.getAffineX().toByteArray();
        if (x.length > fieldSize) {
            // Remove leading zeros if present
            x = Arrays.copyOfRange(x, x.length - fieldSize, x.length);
        } else if (x.length < fieldSize) {
            // Pad with zeros if needed
            byte[] padded = new byte[fieldSize];
            System.arraycopy(x, 0, padded, fieldSize - x.length, x.length);
            x = padded;
        }
        System.arraycopy(x, 0, encoded, 1, fieldSize);
        
        // Convert Y coordinate to fieldSize bytes, big-endian
        byte[] y = w.getAffineY().toByteArray();
        if (y.length > fieldSize) {
            // Remove leading zeros if present
            y = Arrays.copyOfRange(y, y.length - fieldSize, y.length);
        } else if (y.length < fieldSize) {
            // Pad with zeros if needed
            byte[] padded = new byte[fieldSize];
            System.arraycopy(y, 0, padded, fieldSize - y.length, y.length);
            y = padded;
        }
        System.arraycopy(y, 0, encoded, 1 + fieldSize, fieldSize);
        
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
        ECPublicKey that = (ECPublicKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }

    @Override
    public ECPoint getW() {
        if (w == null && keyBytes != null) {
            // Convert from encoded format (0x04 || X || Y)
            if (keyBytes[0] != 0x04) {
                throw new IllegalStateException("Invalid public key encoding");
            }

            int fieldSize = (keyBytes.length - 1) / 2;
            byte[] x = Arrays.copyOfRange(keyBytes, 1, 1 + fieldSize);
            byte[] y = Arrays.copyOfRange(keyBytes, 1 + fieldSize, keyBytes.length);

            w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        }
        return w;
    }
}
