package com.aws.greengrass.security.provider.parsec;

import lombok.RequiredArgsConstructor;
import software.amazon.awssdk.crt.io.TlsHashAlgorithm;
import software.amazon.awssdk.crt.io.TlsKeyOperation;
import software.amazon.awssdk.crt.io.TlsKeyOperationHandler;
import software.amazon.awssdk.crt.io.TlsSignatureAlgorithm;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

/**
 *
 */
@RequiredArgsConstructor
public class ParsecKeyOperationHandler implements TlsKeyOperationHandler {
    final PrivateKey key;
    final Provider provider;

    public void performOperation(TlsKeyOperation operation) {
        System.out.println("perform operation " + operation);
        try {
            if (operation.getType() != TlsKeyOperation.Type.SIGN) {
                throw new RuntimeException("Simple sample only handles SIGN operations");
            }

            if (operation.getSignatureAlgorithm() != TlsSignatureAlgorithm.RSA) {
                throw new RuntimeException("Simple sample only handles RSA keys");
            }

            if (operation.getDigestAlgorithm() != TlsHashAlgorithm.SHA256) {
                throw new RuntimeException("Simple sample only handles SHA256 digests");
            }

            byte[] digest = operation.getInput();
            Signature rsaSign = Signature.getInstance("SHA256withRSA", provider);
            rsaSign.initSign(key);
            rsaSign.update(digest);
            byte[] signatureBytes = rsaSign.sign();
            operation.complete(signatureBytes);

        } catch (Exception ex) {
            System.out.println("Error during key operation:" + ex);
            operation.completeExceptionally(ex);
        }
    }
}
