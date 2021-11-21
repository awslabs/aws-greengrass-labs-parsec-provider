package com.aws.greengrass.security.provider.parsec;

import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.provisioning.DeviceIdentityInterface;
import com.aws.greengrass.provisioning.ProvisionConfiguration;
import com.aws.greengrass.provisioning.ProvisionContext;
import com.aws.greengrass.provisioning.exceptions.RetryableProvisioningException;

/**
 *
 */
public class ParsecDeviceIdentity implements DeviceIdentityInterface {

  protected final Logger logger;

  public ParsecDeviceIdentity(){
    this.logger = LogManager.getLogger(this.getClass()).createChild();
  }

  @Override
  public ProvisionConfiguration updateIdentityConfiguration(ProvisionContext provisionContext)
      throws RetryableProvisioningException, InterruptedException {
    logger.info("Updating Device Identity Configuration via Parsec Provisioning");
    return ProvisionConfiguration.builder()
        .nucleusConfiguration(ProvisionConfiguration.NucleusConfiguration.builder().build())
        .systemConfiguration(ProvisionConfiguration.SystemConfiguration.builder()
            .certificateFilePath("parsec:object=ggeulachtoken;type=cert")
            .privateKeyPath("parsec:object=ggeulachtoken;type=private")
            .build()).build();
  }

  @Override
  public String name() {
    return this.getClass().getSimpleName();
  }
}
