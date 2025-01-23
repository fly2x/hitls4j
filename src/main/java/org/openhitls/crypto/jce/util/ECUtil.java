package org.openhitls.crypto.jce.util;

import java.security.spec.*;
import java.math.BigInteger;

import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

public class ECUtil {
    // NIST P-256 (secp256r1) parameters
    private static final BigInteger P256_ORDER = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger P256_P = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    
    // NIST P-384 (secp384r1) parameters
    private static final BigInteger P384_ORDER = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16);
    private static final BigInteger P384_P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);
    
    // NIST P-521 (secp521r1) parameters
    private static final BigInteger P521_ORDER = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16);
    private static final BigInteger P521_P = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
    
    // SM2 (sm2p256v1) parameters
    private static final BigInteger SM2_ORDER = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    private static final BigInteger SM2_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);

    /**
     * Identifies the curve name from ECParameterSpec
     */
    public static String getCurveName(ECParameterSpec params) {
        if (params == null) {
            throw new IllegalArgumentException("ECParameterSpec cannot be null");
        }

        // First check if it's already a named curve
        if (params instanceof ECNamedCurveSpec) {
            return ((ECNamedCurveSpec)params).getName();
        }

        // Otherwise identify by field size and order
        int fieldSize = params.getCurve().getField().getFieldSize();
        BigInteger order = params.getOrder();
        BigInteger p = ((ECFieldFp)params.getCurve().getField()).getP();

        // Identify curve by field size, order and prime
        if (fieldSize == 256) {
            if (order.equals(P256_ORDER) && p.equals(P256_P)) {
                return "secp256r1";
            } else if (order.equals(SM2_ORDER) && p.equals(SM2_P)) {
                return "sm2p256v1";
            }
        } else if (fieldSize == 384) {
            if (order.equals(P384_ORDER) && p.equals(P384_P)) {
                return "secp384r1";
            }
        } else if (fieldSize == 521) {
            if (order.equals(P521_ORDER) && p.equals(P521_P)) {
                return "secp521r1";
            }
        }

        throw new IllegalArgumentException("Unsupported curve parameters");
    }

    /**
     * Converts field size in bits to bytes, rounding up
     */
    public static int getFieldSize(ECParameterSpec params) {
        return (params.getCurve().getField().getFieldSize() + 7) / 8;
    }

    /**
     * Pads or trims a byte array to the specified length
     */
    public static byte[] padOrTrim(byte[] input, int length) {
        if (input.length == length) {
            return input;
        }
        
        byte[] result = new byte[length];
        if (input.length > length) {
            // Trim from the left (preserve least significant bytes)
            System.arraycopy(input, input.length - length, result, 0, length);
        } else {
            // Pad with zeros on the left
            System.arraycopy(input, 0, result, length - input.length, input.length);
        }
        return result;
    }
} 