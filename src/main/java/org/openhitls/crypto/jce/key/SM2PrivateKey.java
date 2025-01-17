package org.openhitls.crypto.jce.key;

import java.security.PrivateKey;
import java.util.Arrays;

public class SM2PrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;
    private final byte[] keyBytes;

    public SM2PrivateKey(byte[] keyBytes) {
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
        SM2PrivateKey that = (SM2PrivateKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }
}
