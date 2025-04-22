# Valkey Audit Module

This module provides comprehensive auditing capabilities for Valkey servers. It allows logging of various event types to different output protocols with configurable formatting.

## Features

- **Multiple logging protocols**: File system and Syslog support
- **Configurable formats**: Text, JSON, and CSV output formats
- **Selective event auditing**: Configure which events to audit
- **Command payload options**: Control whether and how much of command payloads to include

## Build Instructions

ValkeyAudit uses CMake for building the Valkey module.

```bash
mkdir build
cmake -S . -B build
cmake --build build --target all
```
## Installation

### Loading the Module

Add the following line to your Valkey configuration file:

```
loadmodule /path/to/libvalkeyaudit.so
```

You can also specify initial configuration parameters:

```
loadmodule /path/to/libvalkeyaudit.so protocol file logfile /path/to/audit.log format json events all
```

Available loading parameters:
- `protocol [file|syslog]`: Logging protocol to use
- `logfile [path]`: Path to the audit log file (for file protocol)
- `format [text|json|csv]`: Log format
- `syslog-facility [facility]`: Syslog facility (for syslog protocol)
- `events [event1,event2,...]`: Event categories to audit (connections,auth,config,keys)
- `disable-payload`: Disable logging command payloads
- `max-payload-size [size]`: Maximum payload size to log

## Usage

The module provides the following commands:

### audit.setprotocol

Sets the audit logging protocol.

```
AUDIT.SETPROTOCOL file /path/to/logfile
AUDIT.SETPROTOCOL syslog local0
```

### audit.setformat

Sets the audit log format.

```
AUDIT.SETFORMAT text
AUDIT.SETFORMAT json
AUDIT.SETFORMAT csv
```

### audit.setevents

Sets which event categories to audit.

```
AUDIT.SETEVENTS all          # Enable all events
AUDIT.SETEVENTS none         # Disable all events
AUDIT.SETEVENTS connections auth  # Enable only connection and auth events
```

Available event categories:
- `connections`: Client connections and disconnections
- `auth`: Authentication attempts (with password redaction)
- `config`: Configuration commands
- `keys`: Key operations

### audit.setpayloadoptions

Configures options for payload logging.

```
AUDIT.SETPAYLOADOPTIONS disable yes|no
AUDIT.SETPAYLOADOPTIONS maxsize 1024
```

### audit.getconfig

Retrieves the current audit configuration.

```
AUDIT.GETCONFIG
```

### audit.setexcludeusers

Set usernames to be excluded from auditing through a comma-separated list.

```
AUDIT.SETEXCLUDEUSERS <un1, un2>
```

### audit.clearexcludeusers

Remove the current list of usernames to be excluded from auditing.

```
AUDIT.CLEAREXCLUDEUSERS
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

## Unit Tests

The unit tests are written in python and can be found in the test/unit directory. They will start a local valkey server with the module loaded.
Requirements:
- valkey installation, environment variable VALKEY_SERVER if not in the path
- environment variable AUDIT_MODULE_PATH to point at the module shared library libvalkeyaudit.so
  
To do: automation

## Logged Events

### Connection Events

Example in text format:
```
[2025-04-15 14:30:22] [CONNECTION] CONNECTED client_id=0x7f8a1c003a40
[2025-04-15 14:35:15] [CONNECTION] DISCONNECTED client_id=0x7f8a1c003a40
```

### Authentication Events

Example in text format (password is always redacted):
```
[2025-04-15 14:30:25] [AUTH] ATTEMPT password=<REDACTED>
```

### Configuration Commands

Example in text format:
```
[2025-04-15 14:32:10] [CONFIG] GET param=port
[2025-04-15 14:33:05] [CONFIG] SET param=maxclients
```

### Key Operations

Example in text format:
```
[2025-04-15 14:31:18] [KEY_OP] SET key=user:1001 payload={"name":"John","email":"john@example.com"}
```

## License

This module is licensed under the same terms as Valkey itself.
