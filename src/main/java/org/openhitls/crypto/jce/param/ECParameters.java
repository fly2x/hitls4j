package org.openhitls.crypto.jce.param;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.AlgorithmParametersSpi;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;

import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

/**
 * EC algorithm parameters implementation.
 */
public class ECParameters extends AlgorithmParametersSpi {
    private ECParameterSpec ecParameterSpec;
    private String name;

    // Map of supported curves
    private static final Map<String, ECParameterSpec> namedCurves = new HashMap<>();

    static {
        // Initialize supported curves
        namedCurves.put("sm2p256v1", ECNamedCurveSpec.getSM2Curve());
        namedCurves.put("secp256r1", ECNamedCurveSpec.getP256Curve());
        namedCurves.put("secp384r1", ECNamedCurveSpec.getP384Curve());
        namedCurves.put("secp521r1", ECNamedCurveSpec.getP521Curve());
        
        // Add aliases for NIST curves
        namedCurves.put("prime256v1", ECNamedCurveSpec.getP256Curve());  // Alias for secp256r1
        namedCurves.put("p-256", ECNamedCurveSpec.getP256Curve());       // Another common alias
        namedCurves.put("p-384", ECNamedCurveSpec.getP384Curve());       // Alias for secp384r1
        namedCurves.put("p-521", ECNamedCurveSpec.getP521Curve());       // Alias for secp521r1
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec instanceof ECParameterSpec) {
            ecParameterSpec = (ECParameterSpec)paramSpec;
            if (paramSpec instanceof ECNamedCurveSpec) {
                name = ((ECNamedCurveSpec)paramSpec).getName();
            }
        } else if (paramSpec instanceof ECGenParameterSpec) {
            name = ((ECGenParameterSpec)paramSpec).getName().toLowerCase();
            ECParameterSpec spec = namedCurves.get(name);
            if (spec != null) {
                ecParameterSpec = spec;
            } else {
                throw new InvalidParameterSpecException("Unknown curve name: " + name);
            }
        } else {
            throw new InvalidParameterSpecException("ECParameterSpec or ECGenParameterSpec required");
        }
    }

    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Not implemented");
    }

    protected void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("Not implemented");
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new NullPointerException("paramSpec == null");
        }

        if (ECParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (ecParameterSpec == null) {
                throw new InvalidParameterSpecException("ECParameterSpec not initialized");
            }
            return (T)ecParameterSpec;
        }

        if (ECGenParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (name != null) {
                return (T)new ECGenParameterSpec(name);
            }
        }

        throw new InvalidParameterSpecException("Unknown parameter spec: " + paramSpec.getName());
    }

    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Not implemented");
    }

    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Not implemented");
    }

    protected String engineToString() {
        return name != null ? name : "Unnamed EC Parameters";
    }

    // Make namedCurves accessible
    public static Map<String, ECParameterSpec> getNamedCurves() {
        return Collections.unmodifiableMap(namedCurves);
    }
}
