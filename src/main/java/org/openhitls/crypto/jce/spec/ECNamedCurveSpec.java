package org.openhitls.crypto.jce.spec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Specification signifying that the curve parameters can also be referred to by name.
 */
public class ECNamedCurveSpec extends java.security.spec.ECParameterSpec {
    private final String name;

    public ECNamedCurveSpec(
        String name,
        EllipticCurve curve,
        ECPoint g,
        BigInteger n) {
        this(name, curve, g, n, BigInteger.ONE);
    }

    public ECNamedCurveSpec(
        String name,
        EllipticCurve curve,
        ECPoint g,
        BigInteger n,
        BigInteger h) {
        super(curve, g, n, h.intValue());
        this.name = name;
    }

    /**
     * Return the name of the curve this specification represents.
     *
     * @return the name of the curve.
     */
    public String getName() {
        return name;
    }

    /**
     * Create parameters for SM2 curve (sm2p256v1).
     */
    public static ECNamedCurveSpec sm2p256v1() {
        BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
        BigInteger a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
        BigInteger n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
        BigInteger h = BigInteger.ONE;
        BigInteger gx = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
        BigInteger gy = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        ECPoint g = new ECPoint(gx, gy);

        return new ECNamedCurveSpec("sm2p256v1", curve, g, n, h);
    }

    public static ECNamedCurveSpec getNamedCurve(String name) {
        switch (name.toLowerCase()) {
            case "sm2p256v1":
                return sm2p256v1();
            case "secp256r1":
                return getP256Curve();
            case "secp384r1":
                return getP384Curve();
            case "secp521r1":
                return getP521Curve();
            default:
                throw new IllegalArgumentException("Unsupported curve: " + name);
        }
    }

    private static ECNamedCurveSpec getP256Curve() {
        BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        BigInteger gx = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
        BigInteger gy = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
        BigInteger n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        BigInteger h = BigInteger.ONE;

        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        ECPoint g = new ECPoint(gx, gy);

        return new ECNamedCurveSpec("secp256r1", curve, g, n, h);
    }

    // Add similar methods for P384 and P521 curves
    // ... getP384Curve() and getP521Curve() implementations ...
}
