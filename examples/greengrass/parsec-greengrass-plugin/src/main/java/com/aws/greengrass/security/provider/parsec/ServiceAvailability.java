package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.security.exceptions.ServiceUnavailableException;

interface ServiceAvailability {
    void check() throws ServiceUnavailableException;
}
