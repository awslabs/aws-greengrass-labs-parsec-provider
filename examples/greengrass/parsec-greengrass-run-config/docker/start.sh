#!/bin/bash
set -e -o pipefail

JAVA_OPTS=""
case "${1}" in
/bin/*sh)
  exec "$@"
  ;;
reprovision)
  GG_PROVISION=true
  GG_START=false
  aws --region "${AWS_REGION}" iot create-thing --thing-name "${GG_THING_NAME}"
  ;;
provision)
  GG_PROVISION=true
  GG_START=false
  aws --region "${AWS_REGION}" iot create-thing --thing-name "${GG_THING_NAME}"
  backup_dir="backup_$(date --iso-8601=ns)"
  mkdir -p "${backup_dir}"
  (find . -maxdepth 1 -mindepth 1 |grep -v ./backup_ | xargs -I {} mv {} "${backup_dir}") || true
  ;;
run)
  GG_PROVISION=false
  GG_START=true
  ;;
esac
if [ "${2}" == "debug" ]; then
  JAVA_OPTS="${JAVA_OPTS} -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005"
  echo "using Debug config ${JAVA_OPTS}"
fi


for mandatory_env in GG_THING_NAME GG_PROVISION GG_START; do
  if [ "${!mandatory_env}" == "" ]; then
    echo "the env variable ${mandatory_env} needs to be set"
      exit 255
  fi
done

for warn_env in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION; do
  if [ "${!warn_env}" == "" ]; then
    # AWS SDKs have a series of strategies for picking up config, env variables is just one
    # of them.
    echo "the env variable ${warn_env} is not set, container might fail later"
  fi
done

if ! test -e /greengrass/config.yml; then
  echo "please map a config file to /greengrass/config.yml"
  exit 255
fi

set -x
# shellcheck disable=SC2086


CMD="java ${JAVA_OPTS}
  -jar /greengrass/lib/Greengrass.jar
  --root /home/ggc_user
  --thing-name ${GG_THING_NAME}
  --thing-group-name GreengrassQuickStartGroup
  --component-default-user ggc_user:ggc_group
  --provision ${GG_PROVISION}
  --setup-system-service false
  --deploy-dev-tools true
  --init-config /greengrass/config.yml
  --start ${GG_START} ${GG_ADDITIONAL_CMD_ARGS}
  "
if [ "${GG_KEEP_RUNNING}" == "true" ]; then
  # shellcheck disable=SC2090
  ${CMD}
  exec sleep 10000
else
  # shellcheck disable=SC2086
  exec ${CMD}
fi

