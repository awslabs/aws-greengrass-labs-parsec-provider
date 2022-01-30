#!/bin/bash -e

cd $(dirname "$0")
source secrets.env

function write_gg_docker_run_config() {
  name="$1"
  echo "${name}"
  xpath -q -e / > ../../../.run/${name}.run.xml <<EOF
<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="${name}" type="docker-deploy" factoryName="docker-image" server-name="Docker">
    <deployment type="docker-image">
      <settings>
        <option name="containerName" value="${name}" />
        <option name="imageTag" value="parallaxsecond/greengrass_patched:latest" />
        <option name="command" value="${2}" />
        <option name="envVars">
          <list>
            <DockerEnvVarImpl>
              <option name="name" value="AWS_ACCESS_KEY_ID" />
              <option name="value" value="${AWS_ACCESS_KEY_ID}" />
            </DockerEnvVarImpl>
            <DockerEnvVarImpl>
              <option name="name" value="AWS_SECRET_ACCESS_KEY" />
              <option name="value" value="${AWS_SECRET_ACCESS_KEY}" />
            </DockerEnvVarImpl>
            <DockerEnvVarImpl>
              <option name="name" value="AWS_REGION" />
              <option name="value" value="${AWS_REGION}" />
            </DockerEnvVarImpl>
            <DockerEnvVarImpl>
              <option name="name" value="GG_ADDITIONAL_CMD_ARGS" />
              <option name="value" value="--trusted-plugin /provider.jar" />
            </DockerEnvVarImpl>
            <DockerEnvVarImpl>
              <option name="name" value="GG_THING_NAME" />
              <option name="value" value="$(id -un)-gg-parsec" />
            </DockerEnvVarImpl>
          </list>
        </option>
        <option name="commandLineOptions" value="-v GG_PARSEC_SOCK:/run/parsec -v GG_HOME:/home/ggc_user" />
        <option name="sourceFilePath" value="examples/greengrass/parsec-greengrass-run-config/docker/Dockerfile" />
        <option name="volumeBindings">
          <list>
            <DockerVolumeBindingImpl>
              <option name="containerPath" value="/provider.jar" />
              <option name="hostPath" value="\$PROJECT_DIR$/examples/greengrass/parsec-greengrass-plugin/target/aws.greengrass.crypto.ParsecProvider.jar" />
            </DockerVolumeBindingImpl>
            <DockerVolumeBindingImpl>
              <option name="containerPath" value="/greengrass/config.yml" />
              <option name="hostPath" value="\$PROJECT_DIR$/examples/greengrass/parsec-greengrass-run-config/config.yml" />
            </DockerVolumeBindingImpl>
          </list>
        </option>
      </settings>
    </deployment>
    <method v="2">
      <option name="RunConfigurationTask" enabled="true" run_configuration_name="parsec_docker_run" run_configuration_type="docker-deploy" />
      <option name="Maven.BeforeRunTask" enabled="true" file="\$PROJECT_DIR$/pom.xml" goal="-o -pl examples/greengrass/parsec-greengrass-plugin package -DskipTests=true" />
    </method>
  </configuration>
</component>
EOF
}

function write_gg_docker_debug_config() {
  xpath -q -e / > "../../../.run/${1} (debug).run.xml" << EOF
<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="${1} (debug)" type="Remote">
    <module name="parsec-greengrass-plugin" />
    <option name="USE_SOCKET_TRANSPORT" value="true" />
    <option name="SERVER_MODE" value="false" />
    <option name="SHMEM_ADDRESS" />
    <option name="HOST" value="localhost" />
    <option name="PORT" value="5005" />
    <option name="AUTO_RESTART" value="false" />
    <method v="2">
      <option name="RunConfigurationTask" enabled="true" run_configuration_name="parsec_docker_run" run_configuration_type="docker-deploy" />
      <option name="Maven.BeforeRunTask" enabled="true" file="\$PROJECT_DIR$/pom.xml" goal="-o -pl examples/greengrass/parsec-greengrass-plugin package -DskipTests=true" />
      <option name="com.intellij.docker.debug.DockerBeforeRunTask" command="${2} debug" run-config="${1}" />
    </method>
  </configuration>
</component>
EOF
}

function write_parsec_docker_run_config() {
  echo "parsec_docker_run"
  xpath -q -e / > ../../../.run/parsec_docker_run.run.xml <<EOF
<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="parsec_docker_run" type="docker-deploy" factoryName="docker-image" server-name="Docker">
    <deployment type="docker-image">
      <settings>
        <option name="imageTag" value="parallaxsecond/parsec:0.8.1" />
        <option name="containerName" value="parsec_docker_run" />
        <option name="commandLineOptions" value="-v GG_PARSEC_SOCK:/run/parsec -v GG_PARSEC_STORE:/var/lib/parsec/mappings" />
      </settings>
    </deployment>
    <method v="2">
      <option name="Maven.BeforeRunTask" enabled="true" file="\$PROJECT_DIR$/pom.xml" goal="-pl parsec-testcontainers package -DskipTests=true" />
    </method>
  </configuration>
</component>
EOF
}

write_parsec_docker_run_config
write_gg_docker_run_config gg_docker_provision provision
write_gg_docker_run_config gg_docker_run run
write_gg_docker_debug_config gg_docker_provision provision
write_gg_docker_debug_config gg_docker_run run


if [ "$1" == "-y" ]; then
  delete_volumes="y"
else
  echo "delete volumes [y/n]?"
  read delete_volumes
fi
if [ "${delete_volumes}" == "y" ]; then
  for v in GG_PARSEC_SOCK GG_PARSEC_STORE GG_HOME; do
    echo -n "deleting volume "
    docker volume rm -f "${v}"
  done
fi

