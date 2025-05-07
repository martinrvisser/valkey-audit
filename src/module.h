// module.h
#ifndef MODULE_H
#define MODULE_H

#define MAX_LOG_SIZE 10000
#define MAX_BUFFER_SIZE 1024
#define USERNAME_HASH_SIZE 1024
#define COMMAND_TABLE_SIZE 64

// Protocol types
#define PROTOCOL_FILE 0
#define PROTOCOL_SYSLOG 1

// Event categories
#define EVENT_CONNECTIONS (1<<0)
#define EVENT_AUTH (1<<1)
#define EVENT_CONFIG (1<<2)
#define EVENT_KEYS (1<<3)

// Event format types
#define FORMAT_TEXT 0
#define FORMAT_JSON 1
#define FORMAT_CSV 2

typedef struct AuditConfig {
    int enabled;
    int protocol;
    int format;
    int event_mask;
    int disable_payload;
    size_t max_payload_size;
    char *file_path;
    int syslog_facility;
    int syslog_priority;
    int file_fd;
    int always_audit_config;
} AuditConfig;

typedef struct ConnectionStats {
    size_t total_connections;
    size_t active_connections;
    size_t auth_failures;
    time_t start_time;
} ConnectionStats;

// Define a hash table structure for client ID to username mapping
typedef struct ClientUsernameEntry {
    uint64_t client_id;
    char *username;
    char *ip_address;
    int no_audit; // indicator if the user's commands should not be logged
    struct ClientUsernameEntry *next;
} ClientUsernameEntry;

typedef struct ExclusionRule {
    char *username;     // Can be NULL for IP-only rules
    char *ip_address;   // Can be NULL for username-only rules
    struct ExclusionRule *next;
} ExclusionRule;

// Structure to hold excluded usernames in a linked list
typedef struct ExcludedUsernameNode {
    char *username;
    struct ExcludedUsernameNode *next;
} ExcludedUsernameNode;

typedef struct AuditModuleCommandInfo {
    int firstkey;    // Index of first key argument
    int lastkey;     // Index of last key argument (-1 for unlimited)
    int keystep;     // Step between key arguments
    int flags;       // Command flags
} AuditModuleCommandInfo;

// Structure to hold command definitions
typedef struct {
    const char *name;
    int firstkey;
    int lastkey;
    int keystep;
    int flags;
} CommandDefinition;

#endif // MODULE_H