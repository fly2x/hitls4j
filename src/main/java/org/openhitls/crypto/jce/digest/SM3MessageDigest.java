package org.openhitls.crypto.jce.digest;

import org.openhitls.crypto.core.hash.SM3;
import java.security.MessageDigestSpi;

public class SM3MessageDigest extends MessageDigestSpi {
    private SM3 sm3;

    public SM3MessageDigest() {
        this.sm3 = new SM3();
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (input == null) {
            throw new IllegalArgumentException("Input buffer cannot be null");
        }
        if (offset < 0 || len < 0 || offset + len > input.length) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        if (len == 0) {
            return;
        }

        byte[] data;
        if (offset == 0 && len == input.length) {
            data = input;
        } else {
            data = new byte[len];
            System.arraycopy(input, offset, data, 0, len);
        }
        sm3.update(data);
    }

    @Override
    protected byte[] engineDigest() {
        return sm3.doFinal();
    }

    @Override
    protected void engineReset() {
        sm3 = new SM3();
    }

    @Override
    protected int engineGetDigestLength() {
        return 32; // SM3 hash length is always 32 bytes
    }
}
