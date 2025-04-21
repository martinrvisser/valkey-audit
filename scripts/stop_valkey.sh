#!/bin/bash

if [[ ! $PWD/ = */valkey-audit/* ]]; then
    echo "ERROR: run this script from the repo directory"
    exit 1
fi

while [[ ! $PWD/ = */valkey-audit/ ]]; do
    cd ..
done

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-audit -q`

if [ -z $DOCKER_COMPOSE_RUNNING ]; then
    echo "ERROR: valkey container is not running"
    exit 1
fi

pushd scripts/docker > /dev/null

docker compose down

popd > /dev/null
