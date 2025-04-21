# ValkeyAudit - Valkey Audit authentication module  

## Build Instructions

ValkeyAudit uses CMake for building the Valkey module.

```bash
mkdir build
cmake -S . -B build
cmake --build build --target all
```

## Manual Module Testing

The project has a collection of scripts to start a Valkey server using docker-compose to easily test the module.

To start a Valkey CLI shell to test the module commands, run:

```bash
./scripts/run_test_cli.sh
```

The above command will start the Valkey server, and opens the valkey CLI shell. When the shell closes, it also stops the Valkey server.

If you just want to start the Valkey server, run:

```bash
./scripts/start_valkey.sh
```

You can connect to the Valkey server from the localhost address.

To stop the servers, run:

```bash
./scripts/stop_valkey.sh
```

## Automated Unit Tests

The unit tests use the [googletest](https://github.com/google/googletest) framework and run using CMake test tool:

To run the tests locally do:

```bash
ctest --test-dir build
```
