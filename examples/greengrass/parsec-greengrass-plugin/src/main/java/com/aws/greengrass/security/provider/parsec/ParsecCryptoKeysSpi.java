package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import lombok.Setter;
import org.parallaxsecond.parsec.client.core.BasicClient;
import org.parallaxsecond.parsec.jce.provider.ParsecProvider;
import org.parallaxsecond.parsec.protobuf.psa_key_attributes.PsaKeyAttributes;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.X509KeyManager;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;

import static com.aws.greengrass.security.provider.parsec.ParsecCipherSuites.RSA_WITH_PKCS1;

public class ParsecCryptoKeysSpi implements CryptoKeySpi {
    private final Logger logger;
    private final ServiceAvailability checkServiceAvailability;

    @Setter
    private ParsecProvider parsecProvider;
    @Setter
    private String parsecSocketPath;

    public ParsecCryptoKeysSpi(ServiceAvailability checkServiceAvailability) {
        this.checkServiceAvailability = checkServiceAvailability;
                this.logger = LogManager.getLogger(this.getClass()).createChild();
    }

    @Override
    public KeyManager[] getKeyManagers(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, KeyLoadingException {
        checkServiceAvailability.check();
        try {
            KeyStore clientCertStore = populateKeystore(privateKeyUri, certificateUri);
            logger.info(String.format("getKeyManagers with privKey %s and cert %s", privateKeyUri.toString(), certificateUri.toString()));

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509", parsecProvider);
            kmf.init(
                    new KeyStoreBuilderParameters(
                            KeyStore.Builder.newInstance(
                                    clientCertStore,
                                    new KeyStore.PasswordProtection("password".toCharArray()))));

            return kmf.getKeyManagers();
        } catch (GeneralSecurityException e) {
            logger.error("error loading key", e);
            throw new KeyLoadingException(e.getMessage());
        }
    }

    @Override
    public KeyPair getKeyPair(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, KeyLoadingException {
        logger.info(String.format("getKeyPair with privKey %s and cert %s",
                privateKeyUri.toString(), certificateUri.toString()));
        checkServiceAvailability.check();

        ParsecURI keyUri = ParsecURI.validatePrivateKeyUri(privateKeyUri);
        String keyLabel = keyUri.getLabel();
        KeyManager[] kms = getKeyManagers(privateKeyUri, certificateUri);

        X509KeyManager x509Km =  ((X509KeyManager) kms[0]);
        X509Certificate certificate = x509Km.getCertificateChain(keyLabel)[0];
        PrivateKey privateKey =x509Km.getPrivateKey(keyLabel);
        return new KeyPair(certificate.getPublicKey(), privateKey);
    }

    @Override
    public String supportedKeyType() {
        logger.info("supportedKeyType called");
        return ParsecURI.PARSEC_SCHEME;
    }



    private KeyStore populateKeystore(URI privateKeyUri, URI certificateUri) throws KeyLoadingException {
        ParsecURI keyUri = ParsecURI.validatePrivateKeyUri(privateKeyUri);
        ParsecURI.validateCertificateUri(certificateUri, keyUri);

        String keyLabel = keyUri.getLabel();
        KeyStore certificateStore = PEMImporter.createKeyStore(new File(certificateUri), keyLabel);
        BasicClient client = parsecProvider.getParsecClientAccessor().get();

        boolean keyAlreadyPresent = client.listKeys().getKeys().stream()
                .anyMatch(ki -> keyLabel.equals(ki.getName()));

        if (keyAlreadyPresent) {
            logger.info("not rewriting key, already present {}", keyLabel);
            return certificateStore;
        }

        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyUri));
            PsaKeyAttributes.KeyAttributes keyAttributes = RSA_WITH_PKCS1.getKeyAttributes();
            client.psaImportKey(keyLabel, keyBytes, keyAttributes);
            return certificateStore;
        } catch (IOException e) {
            logger.error("exception loading private key", e);
            throw new KeyLoadingException(e.getMessage());
        }
    }

    boolean initializeParsecProvider() {
        URI socketUri = URI.create("unix:" + parsecSocketPath);
        ParsecProvider newProvider = ParsecProvider.builder().socketUri(socketUri).build();
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

}
