#!/bin/bash
PRJ_KEY="$HOME/project_keys/svc_acct_key.json"
CFT_VER="0"

docker create \
  --name="${PWD##*/}" \
  --entrypoint /bin/bash \
  --interactive \
  --tty \
  --volume "$PWD":/workspace \
  --env GOOGLE_APPLICATION_CREDENTIALS="$(< "$PRJ_KEY")" \
  --env SERVICE_ACCOUNT_JSON="$(< "$PRJ_KEY")" \
  --hostname="${PWD##*/}" \
  gcr.io/cloud-foundation-cicd/cft/developer-tools:"$CFT_VER"



#CFT_VER="0.9.1"
#
#docker create \
#  --name="${PWD##*/}" \
#  --entrypoint /bin/bash \
#  --interactive \
#  --tty \
#  --volume "$PWD":/workspace \
#  --hostname="${PWD##*/}" \
#  gcr.io/cloud-foundation-cicd/cft/developer-tools:"$CFT_VER"