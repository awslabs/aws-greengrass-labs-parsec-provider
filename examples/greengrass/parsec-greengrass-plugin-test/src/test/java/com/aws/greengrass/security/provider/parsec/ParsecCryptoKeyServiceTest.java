package com.aws.greengrass.security.provider.parsec;

import org.parallaxsecond.testcontainers.ParsecContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;
import org.testcontainers.junit.jupiter.Container;

import java.io.File;

/**
 *
 */
public class ParsecCryptoKeyServiceTest {

  @Container
  ParsecContainer parsecContainer =
      ParsecContainer.withVersion("0.8.1")
          .withFileSystemBind(
              absFile("src/test/resources/mbed-crypto-config.toml"),
              "/etc/parsec/config.toml");


  @Container
  GenericContainer<?> greengrassContainer =
      new GenericContainer<>("parallaxsecond/greengrass-test:latest")
          .withCommand()
          .withExposedPorts(1441, 1442)
          .waitingFor(new HttpWaitStrategy().forPort(80).forStatusCode(200))
          .withFileSystemBind(
              absFile("src/test/resources/nginx-client-auth/init.sh"), "/init.sh");

  private String absFile(String f) {
    return new File(f).getAbsolutePath();
  }

}
