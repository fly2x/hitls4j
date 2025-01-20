package org.openhitls.crypto.jce.spec;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;
import java.math.BigInteger;

public class SM2ParameterSpec extends ECParameterSpec {
    private static final BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    private static final BigInteger b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    private static final BigInteger x = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    private static final BigInteger y = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    private static final BigInteger n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    private static final int h = 1;

    private static final SM2ParameterSpec instance = new SM2ParameterSpec();

    private SM2ParameterSpec() {
        super(
            new EllipticCurve(
                new ECFieldFp(p),
                a,
                b
            ),
            new ECPoint(x, y),
            n,
            h
        );
    }

    public static SM2ParameterSpec getInstance() {
        return instance;
    }
}
