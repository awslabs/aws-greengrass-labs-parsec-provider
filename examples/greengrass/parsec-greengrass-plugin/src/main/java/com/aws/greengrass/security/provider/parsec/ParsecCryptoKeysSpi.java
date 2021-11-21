package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;

import javax.net.ssl.KeyManager;
import java.net.URI;
import java.security.KeyPair;

public interface ParsecCryptoKeysSpi extends CryptoKeySpi {


    default KeyManager[] getKeyManagers(URI var1, URI var2) throws ServiceUnavailableException, KeyLoadingException {
        return null;
    }

    default KeyPair getKeyPair(URI var1, URI var2) throws ServiceUnavailableException, KeyLoadingException {
        return null;
    }

    default String supportedKeyType() {
        return null;
    }

}
