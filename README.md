# Valkey Audit Module

This module provides comprehensive auditing capabilities for Valkey servers. It allows logging of various event types to different output protocols and destinations with configurable formatting.

## Features

- **Multiple logging protocols**: file system, syslog support and TCP support
- **Configurable formats**: text, JSON, and CSV output formats
- **Selective event auditing**: configure which events to audit
- **Command payload options**: control whether and how much of a command payloads to include in the audit message

## Build Instructions

ValkeyAudit uses CMake for building the Valkey module and it requires the `valkeymodule.h` header file from Valkey project (installed using the `valkey-devel` package). 

```bash
mkdir build
cmake -S . -B build
cmake --build build --target all
```

If `valkey-devel` package is not available for your system, you can clone it from the [Valkey repository](https://github.com/valkey-io/valkey) and specify the path using `VALKEY_INCLUDE_DIR`.

```bash
mkdir build
VALKEY_VERSION=9.1.0 
git clone --depth 1 --branch "${VALKEY_VERSION}" https://github.com/valkey-io/valkey.git valkey-src
cmake -S . -B build -DVALKEY_INCLUDE_DIR=./valkey-src/src
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
    When using the tcp protocol it should be followed by the double quoted host:port string.
- `audit.format [text|json|csv]`: Log format.
- `audit.events [event1,event2,...]`: Event categories to audit (connections,auth,config,keys,other,none,all).
- `audit.command_result_mode [all|failures]`: Whether to log all commands (`all`) or only commands that fail or are rejected (`failures`). Default is `failures`.
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
- `audit.ignore_internal_clients` : do not audit internal clients like replication clients


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

### command_result_mode

Controls which command executions produce an audit log entry.

```
CONFIG SET AUDIT.COMMAND_RESULT_MODE failures  # default
CONFIG SET AUDIT.COMMAND_RESULT_MODE all
```

**`failures` (default)** — logs only commands that did not complete successfully:
- Commands that executed but returned an error (e.g. `WRONGTYPE`, out-of-range index)
- Commands rejected before execution: wrong argument count, unknown command, OOM, read-only replica, busy script, etc.
- ACL rejections: `NOPERM` (command, key, channel, or database) and `NOAUTH`

Successful command executions produce no log entry. The server performs an O(1) listener-count check and skips all event preparation for successful commands, so there is zero per-command overhead for clean traffic.

**`all`** — additionally logs every successful command execution. Equivalent in coverage to the pre-execution command filter approach, with the added benefit of capturing actual execution outcome, duration, and keys modified.

Note: this setting takes effect at module load time. Changing it at runtime updates the stored value but the active event subscription does not change until the module is reloaded.

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
These need to be preceeded with a !
```
CONFIG SET audit.prefix_filter "!FT*"
```

#### Excluding commands through a custom category
Custom categories can be created by the user and subsequently added to the events exclusion list

##### Define custom category and associated commands
The format here is "categoryname:commands in this category"
```
CONFIG SET audit.custom_category "flushes:FLUSHDB,FLUSHALL"
```

##### Define custom admin category  
```
CONFIG SET audit.custom_category "admin:CONFIG,ACL,SAVE,BGSAVE"
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

## Log Output Format

Every audit log entry contains the following fields regardless of format:

| Field | Description |
|---|---|
| `timestamp` | Local time in `YYYY-MM-DD HH:MM:SS` |
| `category` | Event category: `CONNECTION`, `AUTH`, `CONFIG`, `KEY_OP`, `OTHER` |
| `command` | Command name as reported by the server (e.g. `set`, `config\|get`) |
| `command_args` | Command-specific arguments (see below) |
| `result` | Outcome: `SUCCESS`, `FAILURE`, `ATTEMPT` |
| `duration_us` | Execution time in microseconds |
| `keys_modified` | Number of keys modified (0 for reads and failures) |
| `client_id` | Numeric Valkey client ID |
| `username` | Authenticated username |
| `client_ip` | Client IP address |
| `client_port` | Client TCP port |
| `server_hostname` | Hostname of the Valkey server |
| `error` | Populated only for rejected events: `rejected=<msg>` or `acl_deny_reason=<reason> acl_object=<name>` |

### command_args by category

| Category | Contents |
|---|---|
| `KEY_OP` | `key=<key> [payload=<value>]` |
| `CONFIG` | `subcommand=<GET\|SET> [param=<name>]` |
| `AUTH` | `password=<REDACTED>` |
| `OTHER` | `arg1=<val> [arg2=<val>] [arg3=<val>]` |
| `CONNECTION` | `type=<connection-type>` |

### Text format

```
[2026-01-21 09:54:07] [KEY_OP] set result=SUCCESS duration_us=6 keys_modified=1 client_id=4 username=default client_ip=127.0.0.1:30414 server_hostname=myserver key=user:1001 payload=hello
[2026-01-21 09:54:08] [KEY_OP] lpush result=FAILURE duration_us=12 keys_modified=0 client_id=4 username=default client_ip=127.0.0.1:30414 server_hostname=myserver key=mystring
[2026-01-21 09:54:09] [AUTH] set result=FAILURE duration_us=3 keys_modified=0 client_id=5 username=keyuser client_ip=127.0.0.1:30415 server_hostname=myserver key=forbidden:key acl_deny_reason=key acl_object=forbidden:key
[2026-01-21 09:54:10] [CONNECTION] connection result=SUCCESS duration_us=0 keys_modified=0 client_id=16 username=default client_ip=127.0.0.1:30416 server_hostname=myserver type=normal
[2026-01-21 09:54:11] [AUTH] AUTH result=ATTEMPT duration_us=0 keys_modified=0 client_id=16 username=alice client_ip=127.0.0.1:30416 server_hostname=myserver password=<REDACTED>
[2026-01-21 09:54:12] [CONFIG] config|get result=SUCCESS duration_us=45 keys_modified=0 client_id=4 username=default client_ip=127.0.0.1:30414 server_hostname=myserver subcommand=GET param=maxmemory
```

### JSON format

Each entry is a single-line JSON object:

```json
{"timestamp":"2026-01-21 09:54:07","category":"KEY_OP","command":"set","command_args":"key=user:1001 payload=hello","result":"SUCCESS","duration_us":6,"keys_modified":1,"client_id":4,"username":"default","client_ip":"127.0.0.1","client_port":30414,"server_hostname":"myserver","error":""}
{"timestamp":"2026-01-21 09:54:08","category":"KEY_OP","command":"lpush","command_args":"key=mystring","result":"FAILURE","duration_us":12,"keys_modified":0,"client_id":4,"username":"default","client_ip":"127.0.0.1","client_port":30414,"server_hostname":"myserver","error":""}
{"timestamp":"2026-01-21 09:54:09","category":"AUTH","command":"set","command_args":"key=forbidden:key","result":"FAILURE","duration_us":3,"keys_modified":0,"client_id":5,"username":"keyuser","client_ip":"127.0.0.1","client_port":30415,"server_hostname":"myserver","error":"acl_deny_reason=key acl_object=forbidden:key"}
```

### CSV format

Columns (13 total): `timestamp`, `category`, `command`, `command_args`, `result`, `duration_us`, `keys_modified`, `client_id`, `username`, `client_ip`, `client_port`, `server_hostname`, `error`. Commas within a field are escaped with a backslash.

```
2026-01-21 09:54:07,KEY_OP,set,key=user:1001 payload=hello,SUCCESS,6,1,4,default,127.0.0.1,30414,myserver,
2026-01-21 09:54:08,KEY_OP,lpush,key=mystring,FAILURE,12,0,4,default,127.0.0.1,30414,myserver,
2026-01-21 09:54:09,AUTH,set,key=forbidden:key,FAILURE,3,0,5,keyuser,127.0.0.1,30415,myserver,acl_deny_reason=key acl_object=forbidden:key
```

## License

This module is licensed under the same terms as Valkey itself.


