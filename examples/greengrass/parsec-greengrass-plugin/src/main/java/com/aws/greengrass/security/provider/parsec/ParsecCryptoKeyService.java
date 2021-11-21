// must be in com.aws.greengrass
package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.MqttConnectionSpi;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.MqttConnectionProviderException;
import com.aws.greengrass.security.exceptions.ServiceProviderConflictException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.Utils;
import org.parallaxsecond.parsec.jce.provider.ParsecProvider;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.security.cert.Certificate;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;

@ImplementsService(name = ParsecCryptoKeyService.PARSEC_SERVICE_NAME, autostart = true)
public class ParsecCryptoKeyService extends PluginService implements CryptoKeySpi, MqttConnectionSpi {

  public static final String PARSEC_SERVICE_NAME = "aws.greengrass.crypto.ParsecProvider";
  public static final String NAME_TOPIC = "name";
  public static final String PARSEC_SOCKET_TOPIC = "name";

  private static final String PARSEC_TYPE_PRIVATE = "private";
  private static final String PARSEC_TYPE_CERT = "cert";

  private final SecurityService securityService;

  private Provider parsecProvider;

  // Parsec configuration
  private String name;
  private String parsecSocketPath;

  @Inject
  public ParsecCryptoKeyService(Topics topics, SecurityService securityService) {
    super(topics);
    this.securityService = securityService;
  }

  @SuppressWarnings("PMD.PreserveStackTrace")
  @Override
  protected void install() throws InterruptedException {
    try {
      logger.info("Installing Parsec Crypto service");
      super.install();
      this.config.lookup(CONFIGURATION_CONFIG_KEY, NAME_TOPIC).subscribe(this::updateName);
      this.config.lookup(CONFIGURATION_CONFIG_KEY, PARSEC_SOCKET_TOPIC).subscribe(this::updateSocket);
    } catch (IllegalArgumentException e) {
      throw new RuntimeException(String.format("Failed to install ParsecCryptoKeyService. "
          + "Make sure that configuration format for %s service is valid.", PARSEC_SERVICE_NAME));
    }
    if (!initializeParsecProvider()) {
      serviceErrored("Can't initialize Parsec");
    }
  }

  private boolean initializeParsecProvider() {
    URI socketUri = URI.create("unix:" + parsecSocketPath);
    Provider newProvider = ParsecProvider.builder().socketUri(socketUri).build();
    if (newProvider != null && removeProviderFromJCA() && addProviderToJCA(newProvider)) {
      this.parsecProvider = newProvider;
      return true;
    }
    return false;

  }

  private boolean removeProviderFromJCA() {
    if (parsecProvider != null) {
      try {
        Security.removeProvider(parsecProvider.getName());
      } catch (SecurityException e) {
        logger.atError().setCause(e).log("Can't remove provider from JCA");
        return false;
      }
    }
    return true;
  }

  private boolean addProviderToJCA(Provider provider) {
    try {
      if (Security.insertProviderAt(provider, 1) != 1) {
        logger.atError().log("Parsec provider was not added to JCA provider list");
        return false;
      }
    } catch (SecurityException e) {
      logger.atError().setCause(e).kv("providerName", provider.getName()).log("Can't add Parsec JCA provider");
      return false;
    }
    return true;
  }

  @Override
  protected void startup() throws InterruptedException {
    try {
      securityService.registerCryptoKeyProvider(this);
      securityService.registerMqttConnectionProvider(this);
    } catch (ServiceProviderConflictException e) {
      serviceErrored(e);
      return;
    }
    super.startup();
  }


  @Override
  public KeyManager[] getKeyManagers(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, KeyLoadingException {
    checkServiceAvailability();
    try {
      logger.info(String.format("getKeyManagers with privKey %s and cert %s",
          privateKeyUri.toString(), certificateUri.toString()));
      KeyStore ks = getKeyStore(privateKeyUri, certificateUri);

      KeyManagerFactory keyManagerFactory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagerFactory.init(ks, null);
      return keyManagerFactory.getKeyManagers();
    } catch (GeneralSecurityException e) {
      String errorMessage = getErrorMessageForRootCause(e,
          String.format("Failed to get key manager for key %s and certificate %s",
              privateKeyUri, certificateUri));
      throw new KeyLoadingException(errorMessage, e);
    }
  }

  private KeyStore getKeyStore(URI privateKeyUri, URI certificateUri) throws KeyLoadingException {
    ParsecURI keyUri = validatePrivateKeyUri(privateKeyUri);
    validateCertificateUri(certificateUri, keyUri);
    String keyLabel = keyUri.getLabel();
    //char[] password = userPin;
    try {

      KeyStore ks = KeyStore.getInstance("X509", "PARSEC");
      // FIXME


      if (!ks.containsAlias(keyLabel)) {
        throw new KeyLoadingException(String.format("Private key or certificate with label %s does not exist. "
            + "Make sure to import both private key and the certificate into PKCS11 device "
            + "with the same label and id.", keyLabel));
      }
      logger.atDebug().log(String.format("Successfully loaded KeyStore with private key %s", keyLabel));
      return ks;
    } catch (GeneralSecurityException e) {
      throw new KeyLoadingException(
          String.format("Failed to get key store for key %s and certificate %s", privateKeyUri,
              certificateUri), e);
    }
  }


  @Override
  public KeyPair getKeyPair(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, KeyLoadingException {
    logger.info(String.format("getKeyPair with privKey %s and cert %s",
        privateKeyUri.toString(), certificateUri.toString()));
    checkServiceAvailability();

    ParsecURI keyUri = validatePrivateKeyUri(privateKeyUri);

    String keyLabel = keyUri.getLabel();
    try {
      KeyStore ks = getKeyStore(privateKeyUri, certificateUri);
      Key pk = ks.getKey(keyLabel, null);
      if (!(pk instanceof PrivateKey)) {
        throw new KeyLoadingException(String.format("Key %s is not a private key", keyLabel));
      }
      // We will get the public key from the certificate.
      // The certificate *must* be signed by the private key for this to work correctly.
      Certificate cert = getCertificateFromKeyStore(ks, keyLabel);

      return new KeyPair(cert.getPublicKey(), (PrivateKey) pk);
    } catch (GeneralSecurityException e) {
      String errorMessage = getErrorMessageForRootCause(e,
          String.format("Failed to get key pair for key %s and certificate %s",
              privateKeyUri, certificateUri));
      throw new KeyLoadingException(errorMessage, e);
    }
  }

  @Override
  public AwsIotMqttConnectionBuilder getMqttConnectionBuilder(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, MqttConnectionProviderException {
    logger.info(String.format("getMqttConnectionBuilder with privKey %s and cert %s",
        privateKeyUri.toString(), certificateUri.toString()));
    return null;
  }

  @Override
  public String supportedKeyType() {
    logger.info("supportedKeyType called");
    return ParsecURI.PARSEC_SCHEME;
  }

  private ParsecURI validatePrivateKeyUri(URI privateKeyUri) throws KeyLoadingException {
    ParsecURI keyUri;
    try {
      keyUri = new ParsecURI(privateKeyUri);
    } catch (IllegalArgumentException e) {
      throw new KeyLoadingException(String.format("Invalid private key URI: %s", privateKeyUri), e);
    }

    if (Utils.isEmpty(keyUri.getLabel())) {
      throw new KeyLoadingException("Empty key label in private key URI");
    }
    if (!PARSEC_TYPE_PRIVATE.equals(keyUri.getType())) {
      throw new KeyLoadingException(String.format("Private key must be a Parsec %s type, but was %s",
          PARSEC_TYPE_PRIVATE, keyUri.getType()));
    }
    return keyUri;
  }

  private ParsecURI validateCertificateUri(URI certUri, ParsecURI keyUri) throws KeyLoadingException {
    ParsecURI certPkcs11Uri;
    try {
      certPkcs11Uri = new ParsecURI(certUri);
    } catch (IllegalArgumentException e) {
      throw new KeyLoadingException(String.format("Invalid certificate URI: %s", certUri), e);
    }
    if (!PARSEC_TYPE_CERT.equals(certPkcs11Uri.getType())) {
      throw new KeyLoadingException(String.format("Certificate must be a Parsec %s type, but was %s",
          PARSEC_TYPE_CERT, certPkcs11Uri.getType()));
    }
    if (!keyUri.getLabel().equals(certPkcs11Uri.getLabel())) {
      throw new KeyLoadingException("Private key and certificate labels must be the same");
    }
    return certPkcs11Uri;
  }

  private void checkServiceAvailability() throws ServiceUnavailableException {
    if (getState() != State.RUNNING) {
      throw new ServiceUnavailableException("Parsec crypto key service is unavailable");
    }
  }

  private void updateName(WhatHappened what, Topic topic) {
    if (topic != null && what != WhatHappened.timestampUpdated) {
      this.name = Coerce.toString(topic);
      if (what != WhatHappened.initialized && !initializeParsecProvider()) {
        serviceErrored("Can't initialize Parsec JCA provider when name update");
      }
    }
  }

  private void updateSocket(WhatHappened what, Topic topic) {
    if (topic != null && what != WhatHappened.timestampUpdated) {
      this.parsecSocketPath = Coerce.toString(topic);
      if (what != WhatHappened.initialized && !initializeParsecProvider()) {
        serviceErrored("Can't initialize Parsec JCA provider when socket update");
      }
    }
  }

  private Certificate getCertificateFromKeyStore(KeyStore keyStore, String certLabel)
      throws KeyStoreException, KeyLoadingException {
    Certificate cert = keyStore.getCertificate(certLabel);
    if (cert == null) {
      throw new KeyLoadingException(
          String.format("Unable to load certificate with the label %s", certLabel));
    }
    return cert;
  }


  private String getErrorMessageForRootCause(Exception exception, String baseMessage) {
    String rootCause = Utils.getUltimateMessage(exception);
    return Utils.isEmpty(baseMessage) ? rootCause : String.join(" ", baseMessage, rootCause);
  }

}