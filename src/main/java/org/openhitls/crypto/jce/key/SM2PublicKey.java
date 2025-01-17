package org.openhitls.crypto.jce.key;

import java.security.PublicKey;
import java.util.Arrays;

public class SM2PublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;
    private final byte[] keyBytes;

    public SM2PublicKey(byte[] keyBytes) {
        this.keyBytes = keyBytes.clone();
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
