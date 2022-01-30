package com.aws.greengrass.security.provider.parsec;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class PEMImporter {

    public static KeyStore createKeyStore(File thingCert, String thingAlias) {
        try {
            final KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            //keystore.setCertificateEntry("ca", createCertificates(caCert)[0]);
            keystore.setCertificateEntry(thingAlias, createCertificates(thingCert)[0]);
            return keystore;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }


    private static X509Certificate[] createCertificates(File certificatePem) throws IOException, CertificateException {
        List<X509Certificate> list = new ArrayList<>();
        for (byte[] bytes : pemToDer(certificatePem)) {
            X509Certificate x509Certificate = generateCertificateFromDER(bytes);
            list.add(x509Certificate);
        }
        return list.toArray(new X509Certificate[0]);
    }

    public static List<byte[]> pemToDer(File pemFile) throws IOException {
        List<byte[]> result = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(pemFile))) {
            String s = r.readLine();
            if (s == null || !s.matches("^----[- ]BEGIN .*")) {
                throw new IllegalArgumentException("No Pem delimiter found");
            }
            StringBuilder b = new StringBuilder();
            while (s != null) {
              if (s.matches("^----[- ]END .*")) {
                    String hexString = b.toString();
                    final byte[] bytes = Base64.getDecoder().decode(hexString);
                    result.add(bytes);
                    b = new StringBuilder();
                } else {
                  if (!s.matches("^----[- ].*")) {
                    b.append(s);
                  }
                }
                s = r.readLine();
            }
        }
        return result;
    }


    private static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

}