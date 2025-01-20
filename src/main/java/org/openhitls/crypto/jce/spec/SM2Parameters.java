package org.openhitls.crypto.jce.spec;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SM2Parameters extends AlgorithmParametersSpi {
    private ECParameterSpec ecParameterSpec;
    private ECGenParameterSpec ecGenParameterSpec;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec instanceof ECParameterSpec) {
            ECParameterSpec spec = (ECParameterSpec) paramSpec;
            ECParameterSpec sm2Spec = SM2ParameterSpec.getInstance();
            
            if (!spec.getCurve().equals(sm2Spec.getCurve()) ||
                !spec.getGenerator().equals(sm2Spec.getGenerator()) ||
                !spec.getOrder().equals(sm2Spec.getOrder()) ||
                spec.getCofactor() != sm2Spec.getCofactor()) {
                throw new InvalidParameterSpecException("Parameters must match SM2 curve");
            }
            
            this.ecParameterSpec = spec;
        } else if (paramSpec instanceof ECGenParameterSpec) {
            ECGenParameterSpec spec = (ECGenParameterSpec) paramSpec;
            if (!"sm2p256v1".equalsIgnoreCase(spec.getName())) {
                throw new InvalidParameterSpecException("Only sm2p256v1 curve is supported");
            }
            this.ecGenParameterSpec = spec;
            this.ecParameterSpec = SM2ParameterSpec.getInstance();
        } else {
            throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec are supported");
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new NullPointerException();
        }

        if (paramSpec.isAssignableFrom(ECParameterSpec.class)) {
            return paramSpec.cast(ecParameterSpec);
        } else if (paramSpec.isAssignableFrom(ECGenParameterSpec.class)) {
            if (ecGenParameterSpec == null) {
                ecGenParameterSpec = new ECGenParameterSpec("sm2p256v1");
            }
            return paramSpec.cast(ecGenParameterSpec);
        }

        throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec are supported");
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected String engineToString() {
        return "SM2 Parameters";
    }
}
