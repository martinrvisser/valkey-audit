#!/bin/bash

if [[ ! $PWD/ = */valkey-audit/* ]]; then
    echo "ERROR: run this script from the repo directory"
    exit 1
fi

while [[ ! $PWD/ = */valkey-audit/ ]]; do
    cd ..
done

DOCKER_COMPOSE_RUNNING=`docker compose ls --filter name=valkey-audit -q && true`

if [ ! -z $DOCKER_COMPOSE_RUNNING ]; then
    echo "The Valkey server is already running"
else
    pushd scripts/docker > /dev/null

    docker compose up -d --wait
    docker compose logs -f > /tmp/valkey-audit.log 2>&1 &

    popd > /dev/null
fi

# Wait for valkey-server to be online
while true; do
    echo "Waiting for Valkey server"
    sleep 1
    nc -z localhost 6379 && break
done