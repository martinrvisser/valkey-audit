# Valkey Audit Module

This module provides comprehensive auditing capabilities for Valkey servers. It allows logging of various event types to different output protocols and destinations with configurable formatting.

## Features

- **Multiple logging protocols**: file system, syslog support and TCP support
- **Configurable formats**: text, JSON, and CSV output formats
- **Selective event auditing**: configure which events to audit
- **Command payload options**: control whether and how much of a command payloads to include in the audit message

## Build Instructions

ValkeyAudit uses CMake for building the Valkey module.

```bash
mkdir build
cmake -S . -B build
cmake --build build --target all
```
## Installation

### Loading the Module

Add the following line to your Valkey configuration file or issue a MODULE LOAD command. As part of the loadmodule, any of the configuration parameters can be set. Examples:

```
loadmodule /path/to/libvalkeyaudit.so
loadmodule /path/to/libvalkeyaudit.so audit.protocol "file /var/log/audit/valkey_audit.log"
```

### Configuring the Module
The module uses the standard Valkey configuration facility which means that parameters can accessed with CONFIG SET and GET as well as written to the valkey.conf file with CONFIG REWRITE or manually.

Available parameters:
- `audit.enabled [yes|no]`: Enable or disable auditing.
- `audit.always_audit_config [yes|no]`: Enable or disable the auditing of config commands regardless of per user events setting. This allows the logging of config commands for a user even if the user is in the exclusion list.
- `audit.protocol [file|syslog|tcp]`: Logging protocol to use. 
    When using the file protocol it should be followed by the filepath.
    When using the syslog protocol it should be followed by the syslog facility.
    When using the syslog protocol it should be followed by the double quoted host:port string.
- `audit.format [text|json|csv]`: Log format.
- `audit.events [event1,event2,...]`: Event categories to audit (connections,auth,config,keys,other,none,all).
- `audit.payload_disable`: Disable logging command payloads.
- `audit.payload_maxsize [size]`: Maximum payload size to log in bytes.
- `audit.excluderules`: Specific usernames and/or IP addresses to exclude from auditing.
- `audit.tcp_host`: Hostname or IP for target TCP destination to write audit messages.
- `audit.tcp_port`: port destination to write audit messages.
- `audit.tcp_timeout_ms`: timeout in ms for establishing TCP connection.
- `audit.tcp_retry_interval_ms`:  retry interval for establishing TCP connections.
- `audit.tcp_max_retries`: maximum number of retries to establish a TCP connection.
- `audit.tcp_buffer_on_disconnect`: buffer messages during disconnected state from target TCP destination.
- `audit.tcp_reconnect_on_failure`: automatic reconnect to TCP destination on failure.
- `audit.auth_result_check_delay_ms`: delay in milliseconds to delay checking for auth success


## Example Usage

### enable/disable
To enable/disable auditing:

```
CONFIG SET AUDIT.ENABLED yes
CONFIG SET AUDIT.ENABLED no
```

To enable/disable always auditing of config commands. This will log config commands irrespective of what events are set to be audited:

```
CONFIG SET AUDIT.ALWAYS_AUDIT_CONFIG yes
CONFIG SET AUDIT.ALWAYS_AUDIT_CONFIG no
```

### protocol

To set the audit logging protocol, use one of:

```
CONFIG SET AUDIT.PROTOCOL "file /path/to/logfile"
CONFIG SET AUDIT.PROTOCOL syslog local0
CONFIG SET AUDIT.PROTOCOL tcp "127.0.0.1:9514"
```

### format

To sets the audit log format:

```
CONFIG SET AUDIT.FORMAT text
CONFIG SET AUDIT.FORMAT json
CONFIG SET AUDIT.FORMAT csv
```

### events

To set the which event categories to audit, use one of the below: 

```
CONFIG SET AUDIT.EVENTS all          # Enable all events
CONFIG SET AUDIT.EVENTS none         # Disable all events
CONFIG SET AUDIT.EVENTS connections,auth  # Enable only connection and auth events
```

Available event categories:
- `connections`: Client connections and disconnections
- `auth`: Authentication attempts (with password redaction)
- `config`: Configuration commands
- `keys`: Key operations
- `other`: Operations that are not config and are not key operations

### payload

Configure options for payload logging:

```
CONFIG SET AUDIT.PAYLOAD_DISABLE yes|no
CONFIG SET AUDIT.PAYLOAD_MAXSIZE 1024
```

### retrieve the current configuration

To retrieve the current complete audit configuration:

```
CONFIG GET AUDIT.*
```

To retrieve the current specific audit configuration parameter:

```
CONFIG GET AUDIT.FORMAT 
```

### excluding users and/or IP addresses

Rules to set usernames and/or IP addresses to be excluded from auditing through a comma-separated list. The rule formats are :
```
username            # for username-only exclusion
@ipaddress          # for IPaddress-only exclusion
username@ipaddress  # combination exclusion
```

Example

```
CONFIG SET AUDIT.EXCLUDERULES "un1,@192.168.1.12,un2@192.168.1.22"
```

To remove the current list of exclusion rules

```
CONFIG SET AUDIT.EXCLUDERULES ""
```
### TCP destination

Setting the TCP connection parameters:
```
CONFIG SET audit.tcp_host 127.0.0.1
CONFIG SET audit.tcp_port 9514
CONFIG SET audit.tcp_timeout_ms 1000
CONFIG SET audit.tcp_retry_interval_ms 3000
CONFIG SET audit.tcp_max_retries 3
```

Behaviour for disconnects:
```
CONFIG SET audit.tcp_buffer_on_disconnect yes
CONFIG SET audit.tcp_reconnect_on_failure yes
```

### Additional exclusion options
Additional options to exclude are available through specific command exclusions, command prefix exclusion (e.g. for modules) and creation of a custom category

#### Exclude specific commands from audit log
```
CONFIG SET audit.exclude_commands "PING,ECHO,TIME"
```

#### Exclude commands by prefix
```
CONFIG SET audit.exclude_commands "!FT*"
```

#### Excluding commands through a custom category
Custom categories can be created by the user and subsequently added to the events exclusion list

##### Define custom category
```
CONFIG SET audit.custom_category flushes "FLUSHDB,FLUSHALL"
```

##### Define custom admin category  
```
CONFIG SET audit.custom_category admin "CONFIG,ACL,SAVE,BGSAVE"
```

##### Then use in event mask
```
CONFIG SET audit.events "connections,auth,flushes,admin"
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
[2025-04-15 14:30:22] [CONNECTION] CONNECTED client_id=16
[2025-04-15 14:35:15] [CONNECTION] DISCONNECTED client_id=16
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

