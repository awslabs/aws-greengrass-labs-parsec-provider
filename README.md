# AWS Greengrass Parsec Provider

Welcome to the Parsec Provider plug-in for AWS IoT Greengrass v2. This community component allows
AWS IoT Greengrass devices to integrate hardware security solutions using the open-source
[Parsec](https://parsec.community) project from [Cloud Native Computing Foundation
(CNCF)](https://www.cncf.io). Starting from the Greengrass v2.8 release, Parsec can be used as an
alternative to the [PKCS#11
Provider](https://docs.aws.amazon.com/greengrass/v2/developerguide/pkcs11-provider-component.html)
to manage the creation and storage of private keys within hardware-enforced security boundaries on a
variety of platforms, including devices that use a Hardware Security Module (HSM) or a Trusted
Platform Module (TPM). With ongoing investment from the open-source community, Parsec is making it
easier and more portable to integrate cloud-native applications with an increasing number of diverse
hardware security solutions.

# Description

The Parsec Provider is a plug-in component (`aws.greengrass.plugin`). It is implemented with Java
and is supplied as a single Java Archive (JAR) file that can be downloaded from this GitHub
repository. The [Greengrass
Nucleus](https://docs.aws.amazon.com/greengrass/v2/developerguide/greengrass-nucleus-component.html)
runs this plug-in in the same Java Virtual Machine (JVM) as the nucleus itself. When it is used, it
takes care of security operations that require the use of private keys that are protected in
hardware. These operations are routed to the Parsec service on the core device. The Parsec service
is then responsible for using the available platform hardware and software interfaces to perform
those operations with the private key. It is conceptually very similar to how the [PKCS#11
Provider](https://docs.aws.amazon.com/greengrass/v2/developerguide/pkcs11-provider-component.html)
component works, except that the Parsec project aims to handle the various interoperability issues
that are often found when using PKCS#11 libraries on different devices.

# Dependencies

To use this component, you will first need to have the Parsec service and the Parsec command-line
tool (`parsec-tool`) installed and configured on your core device. Parsec is a local service on any
given device, so you will need to have it running and available on the same core device where the
Greengrass Nucleus is running. If you are setting up multiple Greengrass core devices, then you will
need to have Parsec installed and configured on all of them.

The method for installing and configuring Parsec depends on the Operating System image that you are
using on your core device. Some customized distributions might contain Parsec already, in which case
no additional steps are needed. If Parsec is not already installed and running, you may be able to
install it using your system's package manager. In other cases, it can be downloaded as a binary or
built from source code. If you are trying out Parsec for the first time, refer to the [Parsec
Getting Started guide](https://parallaxsecond.github.io/parsec-book/getting_started/index.html) to
learn the steps needed to get Parsec installed and running.

Check for the availability of Parsec on your system using the following command:

```
parsec-tool ping
```

If Parsec is installed and running, this command will produce output similar to the following:

```
[INFO ] Service wire protocol version
1.0
```

If the command fails or is not found, this indicates that Parsec is not fully or correctly
installed. Please refer back to the guidelines above and proceed only when you can successfully
execute the `ping` command.

# Limitations

Currently, the Parsec Provider plug-in for AWS IoT Greenrass v2 is only supported on Linux devices.

# Installation and Usage

The AWS IoT Greengrass Core software includes an installer that sets up your device as a Greengrass
core device. To successfully provision your device and register it with the AWS IoT service, you
need a private key and a corresponding certificate in order to establish trust and a secure
connection between your device and the service. There are also various additional resources that
need to exist within the cloud to represent and manage your device once it is connected. The process
of creating all of these assets is collectively known as *provisioning*.

AWS IoT Greengrass v2 supports a variety of provisioning methods, summarised as follows:

- **Automatic** provisioning. The private key, device certificate, and all other resources are
   created automatically within the AWS IoT service at the point where the AWS IoT Greengrass Core
   software is installed on the core device.
- **Manual** provisioning. All resources are created manually. The private key can either be created
   locally on the device hardware, or it can be downloaded from the AWS IoT service.
- **Fleet** provisioning. This is a variant of automatic provisioning where private keys and
   certificates are created on-demand when a device connects to the AWS IoT service for the first
   time.
- **Custom** provisioning. This is also a variant of automatic provisioning, where additional Java
   components are plugged into the AWS IoT Greengrass core installer to run custom actions that
   implement the provisioning process.

When you use the Parsec Provider component, the private key is created and managed inside Parsec,
which means that it is created on your Greengrass core device and never leaves the device. It is not
downloaded from the AWS IoT service. Once you have created the key, you use Parsec tools to create a
Certificate Signing Request (CSR) based on that key. The AWS IoT service can then use this CSR to
create the certificate for your device.

The provisioning method that best supports this workflow is the *manual* provisioning method. So you
will need to use manual provisioning if you wish to use AWS IoT Greengrass with the Parsec Provider
component.

The steps for manual provisioning are provided as part of the [AWS IoT Greengrass v2
Documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#run-greengrass-core-v2-installer-manual).

You will need to follow these steps in order to install and provision your device. The steps vary
depending on whether you wish to create the private key locally on the device, or download a key
from the AWS IoT service. When you are using Parsec, you will *always* be creating the private key
locally on the device using Parsec tools. The steps to do this are documented below. *Please refer
to these steps instead of the "HSM" instructions given in the AWS IoT Greengrass documentation,
because those assume that you are using the PKCS#11 interface rather than Parsec.*

The guinelines below will show you how to follow the AWS IoT Greengrass documentation while
substituting the steps where Parsec tooling is required.

### Retrieve the AWS IoT endpoints

Follow this step exactly according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#retrieve-iot-endpoints).

### Create an AWS IoT thing

Follow this step exactly according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#create-iot-thing).

### Create the thing certificate

To create the thing certificate, you will begin by creating a suitable private key using the
`parsec-tool`. Choose a name for your private key. You may wish to give the key the same name as the
AWS thing. However, please note that the current version of the software requires the key name to be
all in lower case, so you may need to convert the AWS thing name. Or, you can choose another name.
Whatever naming scheme you choose for the key, you will need to remember it later on when you
configure the Greengrass Nucleus component on your core device.

Set the environment variable `KEY_NAME` to be your chosen key name, and then run this commmand:

```
parsec-tool create-rsa-key -s --key-name ${KEY_NAME}
```

This will create a 2048-bit RSA signing key, which is suitable for use as a private key on which to
base your device certificate.

The next step is to create the CSR. The following example creates a CSR whose Common Name is the
same as the AWS thing that you have provisioned. This assumes that the environment variable
`GG_THING_NAME` has been set to the name of the AWS thing. Run the following command:

```
parsec-tool create-csr --key-name ${KEY_NAME} --cn "${GG_THING_NAME}" >iotdevicekey.csr
```

In the above example, the CSR will have a Common Name (CN) that is the same as the name of the AWS
thing that you have provisioned. Should you wish to structure your CSR with different properties,
please refer to the help text for the CSR command as follows:

```
parsec-tool create-csr --help
```

Once you have created the private key and the CSR, the remaining steps to create the thing
certificate are the same as in the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#create-thing-certificate).

### Configure the thing certificate

Follow this step exactly according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#configure-thing-certificate).

### Create a token exchange role

Follow this step exactly according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#create-token-exchange-role).

### Download the certificates to the device

You will mostly follow this step according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#download-thing-certificates).
Follow the steps that describe how to download the certificates onto the device using an HSM. The
steps to do this with Parsec are the same, except that Parsec does not yet support importing
certificates. The `device.pem.crt` file simply needs to be copied into the `greengrass` root folder
of the core device.

### Set up the device environment

Follow this step exactly according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#set-up-device-environment).

### Download the AWS IoT Greengrass Core software

Follow this step exactly according to the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#download-greengrass-core-v2).

## Install the AWS IoT Greengrass Core software

Begin by following the steps in the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#run-greengrass-core-v2-installer-manual).

Download the Parsec Provider component. This is a single Java JAR file called
`aws.greengrass.crypto.ParsecProvider.jar`. You can download the latest version from `TODO - URL`.
You should copy this file into the same folder where you placed the installer in the step above.

Ensure that thw following environment variables are set in the shell on your core device:

- `GG_USER_HOME` should be set to the root folder for the Greengrass user on your core device, such
   as `/greengrass/v2`.
- `KEY_NAME` should be set to the name of the private key that you created earlier.
- `GG_THING_NAME` should be set to the name of the AWS thing that you are provisioning.
- `AWS_REGION` should be set to the name of the AWS region that you are using, such as `us-west-2`.
- `iot_role_alias` should be set to the name of the token exchange role alias from above, such as
   `GreengrassCoreTokenExchangeRoleAlias`.
- `iot_endpoint` should be set to your AWS IoT data endpoint, such as
   `device-data-prefix-ats.iot.us-west-2.amazonaws.com`.
- `cred_endpoint` should be set to your AWS IoT credentials endpoint, such as
   `device-credentials-prefix.credentials.iot.us-west-2.amazonaws.com`.

Now run the following command to create the partial `config.yaml` file from these inputs:

```
cat <<EOF >${GG_USER_HOME}/config.yaml
system:
  certificateFilePath: "parsec:import=${GG_USER_HOME}/device.pem.crt;object=${KEY_NAME};type=cert"
  privateKeyPath: "parsec:object=${KEY_NAME};type=private"
  rootCaPath: "${GG_USER_HOME}/AmazonRootCA1.pem"
  rootpath: ""
  thingName: "${GG_THING_NAME}"
services:
  aws.greengrass.Nucleus:
    componentType: "NUCLEUS"
    configuration:
      awsRegion: "${AWS_REGION}"
      iotRoleAlias: "${iot_role_alias}"
      iotDataEndpoint: "${iot_endpoint}"
      iotCredEndpoint: "${cred_endpoint}"
  aws.greengrass.crypto.ParsecProvider:
    configuration:
      name: "greengrass-parsec-plugin"
      parsecSocket: "/run/parsec/parsec.sock"
EOF
```

Now run the installer, and specify `--init-config` to provide the configuration file that you just
created.

```
sudo -E java -Droot="{GG_USER_HOME}" -Dlog.store=FILE \
  -jar ./GreengrassInstaller/lib/Greengrass.jar \
  --trusted-plugin ./GreengrassInstaller/aws.greengrass.crypto.ParsecProvider.jar \
  --init-config ./GreengrassInstaller/config.yaml \
  --component-default-user ggc_user:ggc_group \
  --setup-system-service true
```

(If you used a folder other than `GreengrassInstaller` when you downloaded the installer, then
substitute the name of your folder in the above command).

Follow the final verification steps from the [AWS IoT Greengrass
documentation](https://docs.aws.amazon.com/greengrass/v2/developerguide/manual-installation.html#run-greengrass-core-v2-installer-manual).

Congratulations! You have now provisioned and installed your AWS IoT Greengrass core device using
Parsec.

# License

This project is licensed under the [Apache-2.0
License](https://www.apache.org/licenses/LICENSE-2.0).
