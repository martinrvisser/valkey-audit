// common.h
#include <stdint.h>

#ifndef COMMON_H
#define COMMON_H

// Protocol types
#define AUDIT_PROTOCOL_FILE 0
#define AUDIT_PROTOCOL_SYSLOG 1
#define AUDIT_PROTOCOL_TCP 2

#define USERNAME_HASH_SIZE 1024
#define COMMAND_TABLE_SIZE 1024

// Snapshot stats
typedef struct {
    int hash_table_size;
    int hash_table_used;
    int user_commands_count;
    int user_commands_max;
    int prefix_filters_count;
    int custom_categories_count;
} AuditFilterStats;

// Runtime counter stats
typedef struct {
    uint64_t prefix_filter_checks;
    uint64_t prefix_filter_matches;
    uint64_t custom_category_matches;
    uint64_t user_command_lookups;
} AuditRuntimeStats;

// Function to get snapshot stats
AuditFilterStats getAuditFilterStats(void);

// Expose the runtime stats for metrics to read
AuditRuntimeStats getAuditRuntimeStats(void);

#endif // COMMON_H