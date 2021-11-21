package com.aws.greengrass.security.provider.parsec;

import lombok.RequiredArgsConstructor;
import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.CrtResource;
import software.amazon.awssdk.crt.CrtRuntimeException;
import software.amazon.awssdk.crt.io.*;
import software.amazon.awssdk.crt.mqtt.*;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 *
 */
@RequiredArgsConstructor
public class ParsecKeyOperationHandler implements TlsKeyOperationHandler {
    final PrivateKey key;
    final Provider provider;
    
    public void performOperation(TlsKeyOperation operation) {
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

        // A SIGN operation's inputData is the 32bytes of the SHA-256 digest.
        // Before doing the RSA signature, we need to construct a PKCS1 v1.5 DigestInfo.
        // See https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
        byte[] digest = operation.getInput();

        // These are the appropriate bytes for the SHA-256 AlgorithmIdentifier:
        // https://tools.ietf.org/html/rfc3447#page-43
        byte[] sha256DigestAlgorithm = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        ByteArrayOutputStream digestInfoStream = new ByteArrayOutputStream();
        digestInfoStream.write(sha256DigestAlgorithm);
        digestInfoStream.write(digest);
        byte[] digestInfo = digestInfoStream.toByteArray();

        // Sign the DigestInfo
        Signature rsaSign = Signature.getInstance("NONEwithRSA", provider);
        rsaSign.initSign(key);
        rsaSign.update(digestInfo);
        byte[] signatureBytes = rsaSign.sign();

        operation.complete(signatureBytes);

      } catch (Exception ex) {
        System.out.println("Error during key operation:" + ex);
        operation.completeExceptionally(ex);
      }
    }
 }
