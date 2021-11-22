// must be in com.aws.greengrass
package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.MqttConnectionSpi;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.MqttConnectionProviderException;
import com.aws.greengrass.security.exceptions.ServiceProviderConflictException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
import lombok.experimental.Delegate;
import software.amazon.awssdk.crt.io.TlsContextCustomKeyOperationOptions;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

import javax.inject.Inject;
import java.net.URI;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;

@ImplementsService(name = ParsecCryptoKeyService.PARSEC_SERVICE_NAME, priority = 0, autostart = true)
public class ParsecCryptoKeyService extends PluginService implements CryptoKeySpi, MqttConnectionSpi {

    public static final String PARSEC_SERVICE_NAME = "aws.greengrass.crypto.ParsecProvider";
    public static final String PARSEC_SOCKET_TOPIC = "parsecSocket";

    @Delegate
    private final ParsecCryptoKeysSpi parsecCryptoKeysSpi;

    @Inject
    public ParsecCryptoKeyService(Topics topics,
                                  SecurityService securityService,
                                  DeviceConfiguration deviceConfiguration) {
        super(topics);
        this.parsecCryptoKeysSpi = new ParsecCryptoKeysSpi();
        this.config.lookup(CONFIGURATION_CONFIG_KEY, PARSEC_SOCKET_TOPIC).subscribe(this::updateSocket);

        try {
            securityService.registerCryptoKeyProvider(this);
            securityService.registerMqttConnectionProvider(this);
            this.parsecCryptoKeysSpi.afterRegistration(deviceConfiguration);
        } catch (ServiceProviderConflictException e) {
            throw new RuntimeException("Provider parsec already registered");
        }
    }


    private void updateSocket(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.parsecCryptoKeysSpi.setParsecSocketPath(Coerce.toString(topic));
            if (!parsecCryptoKeysSpi.initializeParsecProvider()) {
                serviceErrored("Can't initialize Parsec JCA provider when socket update");
            }
        }
    }

    @Override
    public AwsIotMqttConnectionBuilder getMqttConnectionBuilder(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, MqttConnectionProviderException {
                try {
            ParsecKeyOperationHandler myKeyOperationHandler = new ParsecKeyOperationHandler(
                    parsecCryptoKeysSpi.getKeyPair(privateKeyUri, certificateUri).getPrivate(),
                    parsecCryptoKeysSpi.getParsecProvider()
            );
            TlsContextCustomKeyOperationOptions keyOperationOptions = new TlsContextCustomKeyOperationOptions(myKeyOperationHandler)
                .withCertificateFilePath(ParsecURI.validateParsecURI(certificateUri).getImport());
            return AwsIotMqttConnectionBuilder.newMtlsCustomKeyOperationsBuilder(keyOperationOptions);
        } catch (KeyLoadingException e) {
            throw new MqttConnectionProviderException("Failed to load Parsec key.", e);
        }
    }
}