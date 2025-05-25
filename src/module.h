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
#define PROTOCOL_TCP 2

// Event categories
#define EVENT_CONNECTIONS (1<<0)
#define EVENT_AUTH (1<<1)
#define EVENT_CONFIG (1<<2)
#define EVENT_KEYS (1<<3)

// Event format types
#define FORMAT_TEXT 0
#define FORMAT_JSON 1
#define FORMAT_CSV 2

// Fsync policies
#define AOF_FSYNC_NO 0       // Don't fsync, just let the OS handle it (highest performance)
#define AOF_FSYNC_ALWAYS 1   // Fsync after every write (highest durability)
#define AOF_FSYNC_EVERYSEC 2  // Fsync once per second (good compromise)

#define AUDIT_LOG_BUFFER_SIZE (1*1024*1024)   // 1MB buffer
#define AUDIT_LOG_FLUSH_INTERVAL 1000         // Flush every 1000ms

// module config structure
typedef struct AuditConfig {
    int enabled;
    int protocol;
    int format;
    int event_mask;
    int disable_payload;
    size_t max_payload_size;
    char *file_path;
    int file_fd;
    int syslog_facility;
    int syslog_priority;
    int always_audit_config;
    int fsync_policy;

    /* TCP-specific settings */
    char *tcp_host;
    int tcp_port;
    int tcp_timeout_ms;
    int tcp_retry_interval_ms;
    int tcp_max_retries;
    int tcp_reconnect_on_failure;
    int tcp_buffer_on_disconnect;

     /* Internal fields */
     pthread_mutex_t log_mutex;     /* Mutex for thread safety */
     int tcp_socket;                /* Current TCP socket, -1 if not connected */
     int tcp_connected;             /* TCP connection state */
     time_t tcp_last_connect;       /* Last connection attempt time */
     int tcp_retry_count;           /* Current retry count */
     
     /* Circular buffer */
     char *buffer;                  /* Circular buffer for logs */
     size_t buffer_size;            /* Size of the buffer */
     size_t buffer_head;            /* Write position */
     size_t buffer_tail;            /* Read position */
     size_t buffer_used;            /* Number of bytes in buffer */
     pthread_t worker_thread;       /* Background worker thread */
     pthread_mutex_t buffer_mutex;  /* Buffer mutex */
     pthread_cond_t buffer_cond;    /* Buffer condition variable */
     int worker_running;            /* Worker thread state */
     int shutdown_flag;             /* Signal to shutdown */
} AuditConfig;

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