package com.aws.greengrass.security.provider.parsec;

import java.io.*;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

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
    final List<X509Certificate> result = new ArrayList<X509Certificate>();
    final BufferedReader r = new BufferedReader(new FileReader(certificatePem));
    String s = r.readLine();
    if (s == null || !s.contains("BEGIN CERTIFICATE")) {
      r.close();
      throw new IllegalArgumentException("No CERTIFICATE found");
    }
    StringBuilder b = new StringBuilder();
    while (s != null) {
      if (s.contains("END CERTIFICATE")) {
        String hexString = b.toString();
        final byte[] bytes = Base64.getDecoder().decode(hexString);
        X509Certificate cert = generateCertificateFromDER(bytes);
        result.add(cert);
        b = new StringBuilder();
      } else {
        if (!s.startsWith("----")) {
          b.append(s);
        }
      }
      s = r.readLine();
    }
    r.close();

    return result.toArray(new X509Certificate[result.size()]);
  }


  private static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
    final CertificateFactory factory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
  }

}