package org.openhitls.crypto.jce.digest;

import java.security.MessageDigestSpi;
import org.openhitls.crypto.core.hash.MessageDigest;

public class HiTlsMessageDigest extends MessageDigestSpi {
    private MessageDigest md;
    private final String algorithm;
    private final int digestLength;

    protected HiTlsMessageDigest(String algorithm, int digestLength) {
        this.algorithm = algorithm;
        this.digestLength = digestLength;
        this.md = new MessageDigest(algorithm);
    }

    @Override
    protected int engineGetDigestLength() {
        return digestLength;
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] data = new byte[1];
        data[0] = input;
        engineUpdate(data, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        md.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return md.doFinal();
    }

    @Override
    protected void engineReset() {
        // Create a new instance to reset
        this.md = new MessageDigest(algorithm);
    }

    public static final class SHA224 extends HiTlsMessageDigest {
        public SHA224() {
            super("SHA-224", 28);
        }
    }

    public static final class SHA256 extends HiTlsMessageDigest {
        public SHA256() {
            super("SHA-256", 32);
        }
    }

    public static final class SHA384 extends HiTlsMessageDigest {
        public SHA384() {
            super("SHA-384", 48);
        }
    }

    public static final class SHA512 extends HiTlsMessageDigest {
        public SHA512() {
            super("SHA-512", 64);
        }
    }

    public static final class SM3 extends HiTlsMessageDigest {
        public SM3() {
            super("SM3", 32);
        }
    }
}
