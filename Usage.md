# Valkey Audit Module

This module provides comprehensive auditing capabilities for Valkey servers. It allows logging of various event types to different output protocols with configurable formatting.

## Features

- **Multiple logging protocols**: File system and Syslog support
- **Configurable formats**: Text, JSON, and CSV output formats
- **Selective event auditing**: Configure which events to audit
- **Command payload options**: Control whether and how much of command payloads to include

## Building the Module

### Prerequisites

- GCC or compatible C compiler
- Valkey development headers
- Make or similar build tool

### Compilation

```bash
# Using gcc directly
gcc -shared -fPIC -o audit.so audit.c -I/path/to/valkey/src

# Or via a Makefile
make
```

## Installation

### Loading the Module

Add the following line to your Valkey configuration file:

```
loadmodule /path/to/audit.so
```

You can also specify initial configuration parameters:

```
loadmodule /path/to/audit.so protocol file logfile /path/to/audit.log format json events all
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

## Testing

The repository includes Python unit tests that verify the functionality of the audit module.

### Prerequisites

- Python 3.6+
- redis-py client library

### Running the Tests

```bash
# Set environment variables for the test
export VALKEY_SERVER=/path/to/valkey-server
export AUDIT_MODULE_PATH=/path/to/audit.so

# Run the tests
python audit_module_tests.py
```

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
