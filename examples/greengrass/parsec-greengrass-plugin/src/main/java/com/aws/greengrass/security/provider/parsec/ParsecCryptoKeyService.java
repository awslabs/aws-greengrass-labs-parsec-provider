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
import lombok.experimental.Delegate;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.io.TlsContextCustomKeyOperationOptions;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

import javax.inject.Inject;

import java.net.URI;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;

@ImplementsService(name = ParsecCryptoKeyService.PARSEC_SERVICE_NAME, autostart = true)
public class ParsecCryptoKeyService extends PluginService implements CryptoKeySpi, MqttConnectionSpi {

    public static final String PARSEC_SERVICE_NAME = "aws.greengrass.crypto.ParsecProvider";
    public static final String PARSEC_SOCKET_TOPIC = "parsecSocket";
    public static final String PASSWORD = "password";

    @Delegate
    private final ParsecCryptoKeysSpi parsecCryptoKeysSpi;
    private final SecurityService securityService;

    @Inject
    public ParsecCryptoKeyService(Topics topics, SecurityService securityService) {
        super(topics);
        this.securityService = securityService;
        this.parsecCryptoKeysSpi = new ParsecCryptoKeysSpi(this::checkServiceAvailability);
    }


    @SuppressWarnings("PMD.PreserveStackTrace")
    @Override
    protected void install() throws InterruptedException {
        try {
            logger.info("Installing Parsec Crypto service");
            super.install();
            this.config.lookup(CONFIGURATION_CONFIG_KEY, PARSEC_SOCKET_TOPIC).subscribe(this::updateSocket);
            this.config.lookup(CONFIGURATION_CONFIG_KEY, PASSWORD).subscribe(this::updatePassword);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(String.format("Failed to install ParsecCryptoKeyService. "
                    + "Make sure that configuration format for %s service is valid.", PARSEC_SERVICE_NAME));
        }
        if (!parsecCryptoKeysSpi.initializeParsecProvider()) {
            serviceErrored("Can't initialize Parsec");
        }
    }

    @Override
    protected void startup() throws InterruptedException {
        try {
            securityService.registerCryptoKeyProvider(this);
            //securityService.registerMqttConnectionProvider(this);
        } catch (ServiceProviderConflictException e) {
            serviceErrored(e);
            return;
        }
        super.startup();
    }

    private void checkServiceAvailability() throws ServiceUnavailableException {
        if (getState() != State.RUNNING) {
            throw new ServiceUnavailableException("Parsec crypto key service is unavailable");
        }
    }

    private void updateSocket(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.parsecCryptoKeysSpi.setParsecSocketPath(Coerce.toString(topic));
            if (what != WhatHappened.initialized && !parsecCryptoKeysSpi.initializeParsecProvider()) {
                serviceErrored("Can't initialize Parsec JCA provider when socket update");
            }
        }
    }

    private void updatePassword(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.parsecCryptoKeysSpi.setParsecSocketPath(Coerce.toString(topic));
            if (what != WhatHappened.initialized && !parsecCryptoKeysSpi.initializeParsecProvider()) {
                serviceErrored("Can't initialize Parsec JCA provider when socket update");
            }
        }
    }

    @Override
    public AwsIotMqttConnectionBuilder getMqttConnectionBuilder(URI privateKeyUri, URI certificateUri) throws ServiceUnavailableException, MqttConnectionProviderException {
        checkServiceAvailability();
        try {
            ParsecKeyOperationHandler myKeyOperationHandler = new ParsecKeyOperationHandler(parsecCryptoKeysSpi.getKeyPair(privateKeyUri, certificateUri).getPrivate(), parsecCryptoKeysSpi.getParsecProvider());
            TlsContextCustomKeyOperationOptions keyOperationOptions = new TlsContextCustomKeyOperationOptions(myKeyOperationHandler)
                .withCertificateFilePath(certificateUri.getPath());
            return AwsIotMqttConnectionBuilder.newMtlsCustomKeyOperationsBuilder(keyOperationOptions);
        } catch (KeyLoadingException e) {
            throw new MqttConnectionProviderException(String.format("Failed to load Parsec key %. "
                + "Make sure that configuration format for %s service is valid.", PARSEC_SERVICE_NAME));
        }
    }
}