#include "valkeymodule.h"
#include "module.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

static AuditConfig config = {
    .enabled = 1,
    .protocol = PROTOCOL_FILE,
    .format = FORMAT_TEXT,
    .event_mask = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS,
    .disable_payload = 0,
    .max_payload_size = 1024,
    .file_path = "audit.log",
    .syslog_facility = LOG_LOCAL0,
    .syslog_priority = LOG_NOTICE,
    .file_fd = -1
};

// Forward declarations
//static int auditSetProtocol_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc);
//static int auditSetFormat_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc);
//static int auditSetEvents_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc);
//static int auditSetPayloadOptions_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc);
//static int auditGetConfig_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc);

static ValkeyModuleCommandFilter *filter;
static ConnectionStats stats = {0};
static ClientUsernameEntry *username_hash[USERNAME_HASH_SIZE] = {0};

// Hash function for client IDs
static size_t hash_client_id(uint64_t client_id) {
    return client_id % USERNAME_HASH_SIZE;
}

// Global head of the linked list for excluded usernames
static ExcludedUsernameNode *excluded_usernames_head = NULL;

// Hash function for the command lookup
static unsigned long hash_commands(const char *str, size_t len) {
    const unsigned long FNV_PRIME = 0x01000193;
    const unsigned long FNV_OFFSET_BASIS = 0x811c9dc5;
    
    unsigned long hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        hash ^= (unsigned char)str[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

/* Static definition of command info cache */
static AuditModuleCommandInfo *last_cmd_info = NULL;
static char last_cmd_name[64] = "";
static size_t last_cmd_len = 0;

/* Static command info table (hash table) */
static AuditModuleCommandInfo *command_info_table[COMMAND_TABLE_SIZE];
static bool command_table_initialized = false;

static CommandDefinition keyCommands[] = {
    /* String commands */
    {"set", 1, 1, 1, 0},
    {"setnx", 1, 1, 1, 0},
    {"setex", 1, 1, 1, 0},
    {"psetex", 1, 1, 1, 0},
    {"get", 1, 1, 1, 0},
    {"getex", 1, 1, 1, 0},
    {"getdel", 1, 1, 1, 0},
    {"getset", 1, 1, 1, 0},
    {"mget", 1, -1, 1, 0},
    {"mset", 1, -1, 2, 0},
    {"msetnx", 1, -1, 2, 0},
    {"append", 1, 1, 1, 0},
    {"strlen", 1, 1, 1, 0},
    /* Hash commands */
    {"hset", 1, 1, 1, 0},
    {"hsetnx", 1, 1, 1, 0},
    {"hget", 1, 1, 1, 0},
    {"hmset", 1, -1, 1, 0},
    {"hmget", 1, -1, 1, 0},
    {"hgetall", 1, 1, 1, 0},
    {"hdel", 1, 1, 1, 0},
    {"hlen", 1, 1, 1, 0},
    /* List commands */
    {"lpush", 1, 1, 1, 0},
    {"rpush", 1, 1, 1, 0},
    {"lpop", 1, 1, 1, 0},
    {"rpop", 1, 1, 1, 0},
    {"llen", 1, 1, 1, 0},
    {"lindex", 1, 1, 1, 0},
    {"lrange", 1, 1, 1, 0},
    {"ltrim", 1, 1, 1, 0},
    /* Set commands */
    {"sadd", 1, 1, 1, 0},
    {"srem", 1, 1, 1, 0},
    {"smembers", 1, 1, 1, 0},
    {"sismember", 1, 1, 1, 0},
    {"scard", 1, 1, 1, 0},
    /* ZSet commands */
    {"zadd", 1, 1, 1, 0},
    {"zrem", 1, 1, 1, 0},
    {"zrange", 1, 1, 1, 0},
    {"zcard", 1, 1, 1, 0},
    /* Key space commands */
    {"del", 1, -1, 1, 0},
    {"exists", 1, -1, 1, 0},
    {"expire", 1, 1, 1, 0},
    {"pexpire", 1, 1, 1, 0},
    {"expireat", 1, 1, 1, 0},
    {"pexpireat", 1, 1, 1, 0},
    {"ttl", 1, 1, 1, 0},
    {"pttl", 1, 1, 1, 0},
    {"type", 1, 1, 1, 0},
    {"rename", 1, 2, 1, 0},
    {"renamenx", 1, 2, 1, 0},
    /* Multi-key operations */
    {"sunion", 1, -1, 1, 0},
    {"sinter", 1, -1, 1, 0},
    {"sdiff", 1, -1, 1, 0},
    {"sunionstore", 1, -1, 1, 0},
    {"sinterstore", 1, -1, 1, 0},
    {"sdiffstore", 1, -1, 1, 0},
    /* End marker */
    {NULL, 0, 0, 0, 0}
};

AuditModuleCommandInfo* ValkeyModule_GetCommandInfo(const char *cmd_name, size_t cmd_len) {
    if (cmd_name == NULL || cmd_len == 0) {
        return NULL;
    }

    /* Check if we can return the cached command info */
    if (last_cmd_info != NULL &&
        last_cmd_len == cmd_len &&
        strncasecmp(last_cmd_name, cmd_name, cmd_len) == 0) {
        return last_cmd_info;
    }

    /* Initialize the command table if not already done */
    if (!command_table_initialized) {
        // Clear command table
        memset(command_info_table, 0, sizeof(command_info_table));
        
        // Fill command table
        for (int i = 0; keyCommands[i].name != NULL; i++) {
            const char *cmd_str = keyCommands[i].name;
            size_t cmd_str_len = strlen(cmd_str);
            
            // Use FNV-1a hash function
            unsigned long hash = hash_commands(cmd_str, cmd_str_len) % COMMAND_TABLE_SIZE;
            
            // Handle potential collisions with linear probing
            size_t index = hash;
            size_t start_index = index;
            
            while (command_info_table[index] != NULL) {
                index = (index + 1) % COMMAND_TABLE_SIZE;
                if (index == start_index) {
                    // Table is full
                    fprintf(stderr, "Command table is full during initialization\n");
                    exit(EXIT_FAILURE);
                }
            }
            
            // Create and store command info
            AuditModuleCommandInfo *info = malloc(sizeof(AuditModuleCommandInfo));
            if (info == NULL) {
                perror("Failed to allocate memory for command info");
                exit(EXIT_FAILURE);
            }
            
            info->firstkey = keyCommands[i].firstkey;
            info->lastkey = keyCommands[i].lastkey;
            info->keystep = keyCommands[i].keystep;
            info->flags = keyCommands[i].flags;
            
            command_info_table[index] = info;
        }
        command_table_initialized = true;
    }

    /* Lookup the command in the hash table */
    unsigned long hash = hash_commands(cmd_name, cmd_len) % COMMAND_TABLE_SIZE;
    size_t index = hash;
    size_t start_index = index;
    
    do {
        if (command_info_table[index] != NULL) {
            // Find the command that matches this name
            for (int i = 0; keyCommands[i].name != NULL; i++) {
                if (strlen(keyCommands[i].name) == cmd_len && 
                    strncasecmp(cmd_name, keyCommands[i].name, cmd_len) == 0) {
                    // Found the command
                    last_cmd_info = command_info_table[index];
                    strncpy(last_cmd_name, cmd_name, sizeof(last_cmd_name) - 1);
                    last_cmd_name[sizeof(last_cmd_name) - 1] = '\0';
                    last_cmd_len = cmd_len;
                    return last_cmd_info;
                }
            }
        }
        
        // Move to next slot (linear probing)
        index = (index + 1) % COMMAND_TABLE_SIZE;
    } while (index != start_index);

    /* Command not found */
    return NULL;
}


/////   Section for excluded usernames list functions  /////
// Free the entire excluded usernames list
void freeExcludedUsernames() {
    ExcludedUsernameNode *current = excluded_usernames_head;
    while (current != NULL) {
        ExcludedUsernameNode *next = current->next;
        free(current->username);
        free(current);
        current = next;
    }
    excluded_usernames_head = NULL;
}

// Check if a username is in the excluded list
int isUsernameExcluded(const char *username) {
    if (username == NULL) {
        return 0;
    }

    if (excluded_usernames_head == NULL) return 0;
    
    // Use case-insensitive comparison to ensure consistency
    ExcludedUsernameNode *current = excluded_usernames_head;
    while (current != NULL) {
        if (strcasecmp(current->username, username) == 0) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

// Add a username to the excluded list
void addExcludedUsername(const char *username) {
    // Don't add if it's already in the list
    if (isUsernameExcluded(username)) return;
    
    ExcludedUsernameNode *new_node = (ExcludedUsernameNode*)malloc(sizeof(ExcludedUsernameNode));
    if (new_node == NULL) return;  // Out of memory
    
    new_node->username = strdup(username);
    if (new_node->username == NULL) {
        free(new_node);
        return;  // Out of memory
    }
    
    // Add at the beginning of the list
    new_node->next = excluded_usernames_head;
    excluded_usernames_head = new_node;
}

// Parse the comma-separated list and update the excluded usernames list
void updateExcludedUsernames(const char *csv_list) {
    // First, reset all no_audit flags in the client hash table
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; ++i) {
        ClientUsernameEntry *current = username_hash[i];
        while (current != NULL) {
            current->no_audit = 0;
            current = current->next;
        }
    }
    
    // Clear previous entries in the excluded list
    freeExcludedUsernames();

    // If empty list, just return - all flags are already reset
    if (csv_list == NULL || *csv_list == '\0') return;

    // Make a copy of the list so we can modify it
    char *list_copy = strdup(csv_list);
    if (list_copy == NULL) return;

    // Parse the comma-separated values
    char *token = strtok(list_copy, ",");
    while (token != NULL) {
        // Trim whitespace
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') end--;
        *(end + 1) = '\0';

        // Add to list if not empty
        if (*token != '\0') {
            addExcludedUsername(token);

            // Set no_audit flag for matching clients
            for (unsigned int i = 0; i < USERNAME_HASH_SIZE; ++i) {
                ClientUsernameEntry *current = username_hash[i];
                while (current != NULL) {
                    if (strcmp(current->username, token) == 0) {
                        current->no_audit = 1;
                    }
                    current = current->next;
                }
            }
        }

        token = strtok(NULL, ",");
    }

    free(list_copy);
}

/////   Section for client hash table functions  /////
// Find the entry for client_id in the clients hash table
ClientUsernameEntry* getClientEntry(uint64_t client_id) {
    unsigned int hash_index = client_id % USERNAME_HASH_SIZE;
    ClientUsernameEntry *current = username_hash[hash_index];
    
    // Search the linked list for the client_id
    while (current != NULL) {
        if (current->client_id == client_id) {
            return current;
        }
        current = current->next;
    }
    
    return NULL; // Not found
}

// Get username for a client ID
const char *getClientUsername(uint64_t client_id) {
    size_t idx = hash_client_id(client_id);
    
    ClientUsernameEntry *entry = username_hash[idx];
    while (entry) {
        if (entry->client_id == client_id) {
            return entry->username;
        }
        entry = entry->next;
    }
    
    return NULL;  // Not found
}

// Add or update a client ID to username mapping
// also set the no_audit flag if the username is to be excluded
void storeClientUsername(uint64_t client_id, const char *username, int no_audit) {
    // Allocate memory for the new entry
    ClientUsernameEntry *entry = malloc(sizeof(ClientUsernameEntry));
    if (entry == NULL) {
        return;
    }
    
    // Make a copy of the username
    char *username_copy = strdup(username);
    if (username_copy == NULL) {
        // Handle strdup failure
        free(entry);
        return;
    }
    
    // Initialize the entry
    entry->client_id = client_id;
    entry->username = username_copy;
    entry->no_audit = no_audit;
    entry->next = NULL;
    
    // Calculate hash value (using simple modulo hash)
    unsigned int hash_index = client_id % USERNAME_HASH_SIZE;
    
    // Add to hash table with basic collision handling (linked list chaining)
    if (username_hash[hash_index] == NULL) {
        // First entry at this hash index
        username_hash[hash_index] = entry;
    } else {
        // Collision - add to the beginning of the linked list
        // Check if client_id already exists and update it instead
        ClientUsernameEntry *current = username_hash[hash_index];
        ClientUsernameEntry *prev = NULL;
        
        while (current != NULL) {
            if (current->client_id == client_id) {
                // Client ID already exists - update the entry
                free(current->username);  // Free the old username
                current->username = username_copy;
                current->no_audit = no_audit;
                free(entry);  // Free the unused entry
                return;
            }
            prev = current;
            current = current->next;
        }
        
        // Add new entry to the end of the list
        prev->next = entry;
    }
}

// Remove a client ID from the hash table
void removeClientUsername(uint64_t client_id) {
    size_t idx = hash_client_id(client_id);
    
    ClientUsernameEntry *entry = username_hash[idx];
    ClientUsernameEntry *prev = NULL;
    
    while (entry) {
        if (entry->client_id == client_id) {
            if (prev) {
                prev->next = entry->next;
            } else {
                username_hash[idx] = entry->next;
            }
            free(entry->username);
            free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

// Print the contents of the user hash table
void printUserHashContents(ValkeyModuleCtx *ctx) {
    char buffer[4096] = "User hash table contents:\n";
    size_t offset = strlen(buffer);
    size_t remaining = sizeof(buffer) - offset;
    int empty = 1;

    for (size_t i = 0; i < USERNAME_HASH_SIZE; i++) {
        ClientUsernameEntry *entry = username_hash[i];
        
        while (entry && remaining > 0) {
            int written = snprintf(buffer + offset, remaining, 
                                  "Client ID: %llu, Username: %s, NoAudit: %d \n", 
                                  (unsigned long long)entry->client_id, 
                                  entry->username ? entry->username : "NULL",
                                  entry->no_audit);
            
            if (written > 0 && (size_t)written < remaining) {
                offset += written;
                remaining -= written;
                empty = 0;
            } else {
                // Buffer full
                break;
            }
            
            entry = entry->next;
        }
        
        if (remaining <= 0) {
            break;
        }
    }
    
    if (empty) {
        strcat(buffer, "  (empty)\n");
    }
    
    // log to server log for admin viewing
    ValkeyModule_Log(ctx, "notice", "%s", buffer);
}

/////  Logging functions  /////
// Helper function to get formatted timestamp
/*static void getTimeStr(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}*/

// Get client type string
static const char* getClientTypeStr(ValkeyModuleClientInfo *ci) {
    if (ci->flags & (1ULL << 0)) return "normal";
    if (ci->flags & (1ULL << 1)) return "replica";
    if (ci->flags & (1ULL << 2)) return "pubsub";
    return "unknown";
}

// Helper functions for formatting and writing audit logs
static void writeAuditLog(const char *format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    switch(config.protocol) {
        case PROTOCOL_FILE:
            if (config.file_fd != -1) {
                write(config.file_fd, buffer, strlen(buffer));
                write(config.file_fd, "\n", 1);
            }
            break;
        case PROTOCOL_SYSLOG:
            syslog(config.syslog_priority | config.syslog_facility, "%s", buffer);
            break;
    }
}

static void formatEventText(char *buffer, size_t size, const char *category, const char *command, const char *details) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(buffer, size, "[%s] [%s] %s %s", 
             timestamp, category, command, details ? details : "");
}

static void formatEventJson(char *buffer, size_t size, const char *category, const char *command, const char *details) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(buffer, size, 
             "{\"timestamp\":\"%s\",\"category\":\"%s\",\"command\":\"%s\",\"details\":\"%s\"}",
             timestamp, category, command, details ? details : "null");
}

static void formatEventCsv(char *buffer, size_t size, const char *category, const char *command, const char *details) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Escape any commas in the details
    char escaped_details[1024] = "";
    if (details) {
        const char *src = details;
        char *dst = escaped_details;
        while (*src && (dst - escaped_details < sizeof(escaped_details) - 2)) {
            if (*src == ',') {
                *dst++ = '\\';
            }
            *dst++ = *src++;
        }
        *dst = '\0';
    }
    
    snprintf(buffer, size, "%s,%s,%s,%s", 
             timestamp, category, command, escaped_details);
}

static void logAuditEvent(const char *category, const char *command, const char *details) {
    char buffer[4096];
    
    switch(config.format) {
        case FORMAT_JSON:
            formatEventJson(buffer, sizeof(buffer), category, command, details);
            break;
        case FORMAT_CSV:
            formatEventCsv(buffer, sizeof(buffer), category, command, details);
            break;
        case FORMAT_TEXT:
        default:
            formatEventText(buffer, sizeof(buffer), category, command, details);
            break;
    }
    
    writeAuditLog("%s", buffer);
}

/////  Module config  /////
// Get the protocol configuration string
ValkeyModuleString *getAuditProtocol(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    const char *protocol_str = NULL;
    const char *param_str = NULL;
    char *combined_str = NULL;
    size_t len = 0;
    
    // Determine protocol string based on the config struct
    switch(config.protocol) {
        case PROTOCOL_FILE:
            protocol_str = "file";
            param_str = config.file_path ? config.file_path : "";
            break;
        case PROTOCOL_SYSLOG:
            protocol_str = "syslog";
            // Convert facility number to string
            switch(config.syslog_facility) {
                case LOG_LOCAL0: param_str = "local0"; break;
                case LOG_LOCAL1: param_str = "local1"; break;
                case LOG_LOCAL2: param_str = "local2"; break;
                case LOG_LOCAL3: param_str = "local3"; break;
                case LOG_LOCAL4: param_str = "local4"; break;
                case LOG_LOCAL5: param_str = "local5"; break;
                case LOG_LOCAL6: param_str = "local6"; break;
                case LOG_LOCAL7: param_str = "local7"; break;
                case LOG_USER: param_str = "user"; break;
                case LOG_DAEMON: param_str = "daemon"; break;
                default: param_str = "unknown"; break;
            }
            break;
        default:
            protocol_str = "unknown";
            param_str = "";
    }
    
    // Format as "protocol param"
    len = strlen(protocol_str) + strlen(param_str) + 2; // +1 for space, +1 for null terminator
    combined_str = ValkeyModule_Alloc(len);
    if (combined_str) {
        snprintf(combined_str, len, "%s %s", protocol_str, param_str);
        ValkeyModuleString *result = ValkeyModule_CreateString(NULL, combined_str, strlen(combined_str));
        ValkeyModule_Free(combined_str);
        return result;
    }
    
    // Fallback if allocation fails
    return ValkeyModule_CreateString(NULL, protocol_str, strlen(protocol_str));
}

int setAuditProtocol(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    size_t len;
    const char *input = ValkeyModule_StringPtrLen(new_val, &len);
    
    // Process based on protocol type
    if (strncasecmp(input, "file ", 5) == 0) {
        const char *filepath = input + 5;
        
        // Close existing connections
        if (config.protocol == PROTOCOL_FILE && config.file_fd != -1) {
            close(config.file_fd);
            config.file_fd = -1;
        } else if (config.protocol == PROTOCOL_SYSLOG) {
            closelog();
        }
        
        // Free existing file_path if any
        if (config.file_path) {
            free(config.file_path); // Use free() if the original was allocated with strdup/malloc
            config.file_path = NULL;
        }
        
        // Create a new copy of the filepath
        config.file_path = strdup(filepath); // Use strdup if original used malloc/strdup
        if (!config.file_path) {
            *err = ValkeyModule_CreateString(NULL, "ERR Memory allocation failed", 27);
            return VALKEYMODULE_ERR;
        }
        
        // Update config
        config.protocol = PROTOCOL_FILE;
        
        // Open the file
        config.file_fd = open(config.file_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (config.file_fd == -1) {
            *err = ValkeyModule_CreateString(NULL, "ERR Failed to open audit log file", 32);
            return VALKEYMODULE_ERR;
        }
        
        return VALKEYMODULE_OK;
    } 
    else if (strncasecmp(input, "syslog ", 7) == 0) {
        const char *facility_str = input + 7;
        int facility = LOG_LOCAL0;  // Default
        
        // Simple facility mapping
        if (strcasecmp(facility_str, "local0") == 0) facility = LOG_LOCAL0;
        else if (strcasecmp(facility_str, "local1") == 0) facility = LOG_LOCAL1;
        else if (strcasecmp(facility_str, "local2") == 0) facility = LOG_LOCAL2;
        else if (strcasecmp(facility_str, "local3") == 0) facility = LOG_LOCAL3;
        else if (strcasecmp(facility_str, "local4") == 0) facility = LOG_LOCAL4;
        else if (strcasecmp(facility_str, "local5") == 0) facility = LOG_LOCAL5;
        else if (strcasecmp(facility_str, "local6") == 0) facility = LOG_LOCAL6;
        else if (strcasecmp(facility_str, "local7") == 0) facility = LOG_LOCAL7;
        else if (strcasecmp(facility_str, "user") == 0) facility = LOG_USER;
        else if (strcasecmp(facility_str, "daemon") == 0) facility = LOG_DAEMON;
        else {
            *err = ValkeyModule_CreateString(NULL, "ERR Invalid syslog facility", 27);
            return VALKEYMODULE_ERR;
        }
        
        // Close existing connections
        if (config.protocol == PROTOCOL_FILE && config.file_fd != -1) {
            close(config.file_fd);
            config.file_fd = -1;
        } else if (config.protocol == PROTOCOL_SYSLOG) {
            closelog();
        }
        
        // Free existing file_path if any
        if (config.file_path) {
            free(config.file_path);
            config.file_path = NULL;
        }
        
        // Update config
        config.protocol = PROTOCOL_SYSLOG;
        config.syslog_facility = facility;
        
        // Initialize syslog
        openlog("valkey-audit", LOG_PID, config.syslog_facility);
        
        return VALKEYMODULE_OK;
    } 
    else {
        *err = ValkeyModule_CreateString(NULL, "ERR Unknown protocol. Use 'file <path>' or 'syslog <facility>'", 64);
        return VALKEYMODULE_ERR;
    }
}

// Format config get function
ValkeyModuleString *getAuditFormat(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    const char *formatString;
    
    // Use the format from the config struct
    switch(config.format) {
        case FORMAT_TEXT:
            formatString = "text";
            break;
        case FORMAT_JSON:
            formatString = "json";
            break;
        case FORMAT_CSV:
            formatString = "csv";
            break;
        default:
            formatString = "unknown";
    }
    
    return ValkeyModule_CreateString(NULL, formatString, strlen(formatString));
}

// Format config set function
int setAuditFormat(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    size_t len;
    const char *format = ValkeyModule_StringPtrLen(new_val, &len);
    
    if (strcasecmp(format, "text") == 0) {
        config.format = FORMAT_TEXT;
        logAuditEvent("AUDIT", "SET_FORMAT", "format=text");
        return VALKEYMODULE_OK;
    } else if (strcasecmp(format, "json") == 0) {
        config.format = FORMAT_JSON;
        logAuditEvent("AUDIT", "SET_FORMAT", "format=json");
        return VALKEYMODULE_OK;
    } else if (strcasecmp(format, "csv") == 0) {
        config.format = FORMAT_CSV;
        logAuditEvent("AUDIT", "SET_FORMAT", "format=csv");
        return VALKEYMODULE_OK;
    } else {
        // Create error message
        *err = ValkeyModule_CreateString(NULL, "ERR Unknown format. Use 'text', 'json', or 'csv'", 48);
        return VALKEYMODULE_ERR;
    }
}

// Command implementation: audit.setevents
// Get the events configuration
ValkeyModuleString *getAuditEvents(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    char event_str[256] = "";
    
    // Build string based on the event mask from config
    if (config.event_mask == 0) {
        strcpy(event_str, "none");
    } else if (config.event_mask == (EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS)) {
        strcpy(event_str, "all");
    } else {
        if (config.event_mask & EVENT_CONNECTIONS) strcat(event_str, "connections,");
        if (config.event_mask & EVENT_AUTH) strcat(event_str, "auth,");
        if (config.event_mask & EVENT_CONFIG) strcat(event_str, "config,");
        if (config.event_mask & EVENT_KEYS) strcat(event_str, "keys,");
        
        // Remove trailing comma
        if (strlen(event_str) > 0) {
            event_str[strlen(event_str) - 1] = '\0';
        }
    }
    
    return ValkeyModule_CreateString(NULL, event_str, strlen(event_str));
}

int setAuditEvents(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    size_t len;
    const char *events_input = ValkeyModule_StringPtrLen(new_val, &len);
    
    // Allocate space for parsing
    char *events_copy = ValkeyModule_Alloc(len + 1);
    if (!events_copy) {
        *err = ValkeyModule_CreateString(NULL, "ERR Memory allocation failed", 27);
        return VALKEYMODULE_ERR;
    }
    memcpy(events_copy, events_input, len);
    events_copy[len] = '\0';
    
    // Process special keywords "all" or "none"
    if (strcasecmp(events_copy, "all") == 0) {
        config.event_mask = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS;
        logAuditEvent("AUDIT", "SET_EVENTS", "events=all");
        ValkeyModule_Free(events_copy);
        return VALKEYMODULE_OK;
    } else if (strcasecmp(events_copy, "none") == 0) {
        config.event_mask = 0;
        logAuditEvent("AUDIT", "SET_EVENTS", "events=none");
        ValkeyModule_Free(events_copy);
        return VALKEYMODULE_OK;
    }
    
    // Otherwise, process individual event types separated by commas
    int new_mask = 0;
    char event_str[256] = "";
    char *token, *saveptr;
    
    token = strtok_r(events_copy, ",", &saveptr);
    while (token) {
        // Trim leading and trailing spaces
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';
        
        if (strcasecmp(token, "connections") == 0) {
            new_mask |= EVENT_CONNECTIONS;
            strcat(event_str, "connections,");
        } else if (strcasecmp(token, "auth") == 0) {
            new_mask |= EVENT_AUTH;
            strcat(event_str, "auth,");
        } else if (strcasecmp(token, "config") == 0) {
            new_mask |= EVENT_CONFIG;
            strcat(event_str, "config,");
        } else if (strcasecmp(token, "keys") == 0) {
            new_mask |= EVENT_KEYS;
            strcat(event_str, "keys,");
        } else {
            ValkeyModule_Free(events_copy);
            char error_msg[100];
            snprintf(error_msg, sizeof(error_msg), 
                     "ERR Unknown event type '%s'. Use 'connections', 'auth', 'config', or 'keys'", token);
            *err = ValkeyModule_CreateString(NULL, error_msg, strlen(error_msg));
            return VALKEYMODULE_ERR;
        }
        
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    // Remove trailing comma
    if (strlen(event_str) > 0) {
        event_str[strlen(event_str) - 1] = '\0';
    }
    
    config.event_mask = new_mask;
    
    char details[512];
    snprintf(details, sizeof(details), "events=%s", event_str);
    logAuditEvent("AUDIT", "SET_EVENTS", details);
    
    ValkeyModule_Free(events_copy);
    return VALKEYMODULE_OK;
}

// Command implementation: audit.setpayloadoptions
// Get the payload disable configuration
int getAuditPayloadDisable(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    return config.disable_payload;
}

// Set the payload disable configuration
int setAuditPayloadDisable(const char *name, int new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);
    config.disable_payload = new_val;
    
    char details[32];
    snprintf(details, sizeof(details), "disable=%s", new_val ? "yes" : "no");
    logAuditEvent("AUDIT", "SET_PAYLOAD_OPTIONS", details);
    
    return VALKEYMODULE_OK;
}

// Get the payload maxsize configuration
long long getAuditPayloadMaxSize(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    return config.max_payload_size;
}

// Set the payload maxsize configuration
int setAuditPayloadMaxSize(const char *name, long long new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    if (new_val < 0) {
        *err = ValkeyModule_CreateString(NULL, "ERR Invalid size. Must be a positive number", 44);
        return VALKEYMODULE_ERR;
    }
    
    config.max_payload_size = (size_t)new_val;
    
    char details[64];
    snprintf(details, sizeof(details), "maxsize=%zu", config.max_payload_size);
    logAuditEvent("AUDIT", "SET_PAYLOAD_OPTIONS", details);
    
    return VALKEYMODULE_OK;
}

int getAuditEnabled(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    return config.enabled;
}

int setAuditEnabled(const char *name, int new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);
    config.enabled = new_val;
    return VALKEYMODULE_OK;
}

ValkeyModuleString *getAuditExcludeUsers(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    size_t bufsize = 1024;
    char *buffer = malloc(bufsize);
    if (buffer == NULL) {
        return ValkeyModule_CreateString(NULL, "", 0);
    }
    
    // Build comma-separated list
    buffer[0] = '\0';
    int first = 1;
    ExcludedUsernameNode *current = excluded_usernames_head;
    
    while (current != NULL) {
        size_t username_len = strlen(current->username);
        size_t current_len = strlen(buffer);
        
        // Check if we need to resize the buffer
        if (current_len + username_len + 2 >= bufsize) {
            bufsize *= 2;
            char *new_buffer = realloc(buffer, bufsize);
            if (new_buffer == NULL) {
                free(buffer);
                return ValkeyModule_CreateString(NULL, "", 0);
            }
            buffer = new_buffer;
        }
        
        // Add comma if not the first item
        if (!first) {
            strcat(buffer, ",");
        } else {
            first = 0;
        }
        
        // Add the username
        strcat(buffer, current->username);
        current = current->next;
    }
    
    ValkeyModuleString *result = ValkeyModule_CreateString(NULL, buffer, strlen(buffer));
    free(buffer);
    
    return result;
}

// Set the excluded users configuration for CONFIG SET
int setAuditExcludeUsers(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);
    
    size_t len;
    const char *new_list = ValkeyModule_StringPtrLen(new_val, &len);
    
    // Use the existing updateExcludedUsernames function
    updateExcludedUsernames(new_list);
    
    // Log the event
    char details[100];
    snprintf(details, sizeof(details), "excludeusers=%s", new_list);
    logAuditEvent("AUDIT", "SET_EXCLUDE_USERS", details);
    
    return VALKEYMODULE_OK;
}

// Command implementation: audit.getconfig
static int auditGetConfig_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argc);
    VALKEYMODULE_NOT_USED(argv);
    ValkeyModule_ReplyWithArray(ctx, 5);
    
    // Protocol
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "protocol");
    if (config.protocol == PROTOCOL_FILE) {
        ValkeyModule_ReplyWithArray(ctx, 2);
        ValkeyModule_ReplyWithSimpleString(ctx, "file");
        ValkeyModuleString *fp = ValkeyModule_CreateString(ctx, 
            config.file_path ? config.file_path : "",
            config.file_path ? strlen(config.file_path) : 0);
        ValkeyModule_ReplyWithString(ctx, fp);
    } else {
        ValkeyModule_ReplyWithArray(ctx, 2);
        ValkeyModule_ReplyWithSimpleString(ctx, "syslog");
        
        const char *facility;
        switch (config.syslog_facility) {
            case LOG_LOCAL0: facility = "local0"; break;
            case LOG_LOCAL1: facility = "local1"; break;
            case LOG_LOCAL2: facility = "local2"; break;
            case LOG_LOCAL3: facility = "local3"; break;
            case LOG_LOCAL4: facility = "local4"; break;
            case LOG_LOCAL5: facility = "local5"; break;
            case LOG_LOCAL6: facility = "local6"; break;
            case LOG_LOCAL7: facility = "local7"; break;
            case LOG_USER: facility = "user"; break;
            case LOG_DAEMON: facility = "daemon"; break;
            default: facility = "unknown"; break;
        }
        ValkeyModule_ReplyWithSimpleString(ctx, facility);
    }
    
    // Format
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "format");
    switch (config.format) {
        case FORMAT_TEXT:
            ValkeyModule_ReplyWithSimpleString(ctx, "text");
            break;
        case FORMAT_JSON:
            ValkeyModule_ReplyWithSimpleString(ctx, "json");
            break;
        case FORMAT_CSV:
            ValkeyModule_ReplyWithSimpleString(ctx, "csv");
            break;
        default:
            ValkeyModule_ReplyWithSimpleString(ctx, "unknown");
            break;
    }
    
    // Events
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "events");
    ValkeyModule_ReplyWithArray(ctx, 4);
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "connections");
    ValkeyModule_ReplyWithLongLong(ctx, (config.event_mask & EVENT_CONNECTIONS) ? 1 : 0);
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "auth");
    ValkeyModule_ReplyWithLongLong(ctx, (config.event_mask & EVENT_AUTH) ? 1 : 0);
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "config");
    ValkeyModule_ReplyWithLongLong(ctx, (config.event_mask & EVENT_CONFIG) ? 1 : 0);
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "keys");
    ValkeyModule_ReplyWithLongLong(ctx, (config.event_mask & EVENT_KEYS) ? 1 : 0);
    
    // Payload options
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "payload");
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "disable");
    ValkeyModule_ReplyWithLongLong(ctx, config.disable_payload);
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "maxsize");
    ValkeyModule_ReplyWithLongLong(ctx, config.max_payload_size);
    
    // Stats
    ValkeyModule_ReplyWithArray(ctx, 2);
    ValkeyModule_ReplyWithSimpleString(ctx, "stats");
    ValkeyModule_ReplyWithSimpleString(ctx, "Not implemented yet");
    
    return VALKEYMODULE_OK;
}

// Command to get connection statistics 
int GetConnectionStats_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    ValkeyModule_ReplyWithArray(ctx, 5);
    
    // Calculate uptime
    time_t now = time(NULL);
    time_t uptime = now - stats.start_time;
    
    ValkeyModule_ReplyWithSimpleString(ctx, "total_connections");
    ValkeyModule_ReplyWithLongLong(ctx, stats.total_connections);
    
    ValkeyModule_ReplyWithSimpleString(ctx, "active_connections");
    ValkeyModule_ReplyWithLongLong(ctx, stats.active_connections);
    
    ValkeyModule_ReplyWithSimpleString(ctx, "auth_failures");
    ValkeyModule_ReplyWithLongLong(ctx, stats.auth_failures);
  
    ValkeyModule_ReplyWithSimpleString(ctx, "uptime_seconds");
    ValkeyModule_ReplyWithLongLong(ctx, uptime);
    
    return VALKEYMODULE_OK;
}

// Reset connection statistics
int ResetConnectionStats_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    // Keep active_connections as is, since that's current state
    int active = stats.active_connections;
    
    // Reset stats
    memset(&stats, 0, sizeof(stats));
    stats.active_connections = active;
    stats.start_time = time(NULL);
    
    return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
}

// Command handler for the AUDITUSERS command
int AuditUsersCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);
    
    printUserHashContents(ctx);
    
    // Reply to client
    ValkeyModule_ReplyWithSimpleString(ctx, "OK - user hash table dumped to logs");
    
    return VALKEYMODULE_OK;
}



// Clear all excluded users - to be used when the configuration is set to empty
int clearAuditExcludeUsers(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    // Reset all no_audit flags in the client hash table
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; ++i) {
        ClientUsernameEntry *current = username_hash[i];
        while (current != NULL) {
            current->no_audit = 0;
            current = current->next;
        }
    }
    
    // Free all excluded usernames
    freeExcludedUsernames();
    
    // Log the event
    logAuditEvent("AUDIT", "CLEAR_EXCLUDE_USERS", "");
    
    return VALKEYMODULE_OK;
}

// Command to process the clear excluded users command
int AuditExcludeClearCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);

    // Call freeExcludedUsernames to clear the list
    freeExcludedUsernames();
    
    // Reset all no_audit flags in the client hash table
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; ++i) {
        ClientUsernameEntry *current = username_hash[i];
        while (current != NULL) {
            current->no_audit = 0;
            current = current->next;
        }
    }
    
    ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    return VALKEYMODULE_OK;
}

/////  Callback functions  /////
// Client state change callback
void clientChangeCallback(ValkeyModuleCtx *ctx, ValkeyModuleEvent e, uint64_t sub, void *data) {
    VALKEYMODULE_NOT_USED(e);

    if (config.enabled!=1) return;

    ValkeyModuleClientInfo *ci = data;
    const char *event_type = (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED) ? 
                             "connection" : "disconnection";
    
    // Buffer for the audit message
    char buffer[1024];
    const char *username = "default"; // Default value
    char *temp_username = NULL;       // For tracking allocated memory
    
    if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED) {
        // Client connected - get and store username
        ValkeyModuleString *user_str = ValkeyModule_GetClientUserNameById(ctx, ci->id);

        if (user_str != NULL) {
            size_t user_len;
            const char *user_ptr = ValkeyModule_StringPtrLen(user_str, &user_len);

            // Make a temporary copy for our use in this function
            temp_username = malloc(user_len + 1);
            if (temp_username == NULL) {
                // Handle memory allocation failure
                ValkeyModule_Log(ctx, "warning", "Failed to allocate memory for username");
                ValkeyModule_FreeString(ctx, user_str);
                return; // Or some other error handling
            }
            
            strncpy(temp_username, user_ptr, user_len);
            temp_username[user_len] = '\0'; // Null-terminate the copy
            username = temp_username;       // Use our copy for the audit message

            // Check if username is in the excluded list
            int no_audit = isUsernameExcluded(username);
            
            // Store username in hash table - storeClientUsername makes its own copy
            storeClientUsername(ci->id, username, no_audit);

            ValkeyModule_FreeString(ctx, user_str);
        } else {
            // Handle error cases
            if (errno == ENOENT) {
                username = "non-existent-client";
            } else if (errno == ENOTSUP) {
                username = "no-acl-user";
            } else {
                // Default case for other errors
                username = "unknown-error";
                ValkeyModule_Log(ctx, "warning", "Unknown error getting client username: %d", errno);
            }

            // Store placeholder in hash table
            storeClientUsername(ci->id, username, 0);
        }
    } else if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED) {
        // For disconnection, make a copy of the username from the hash
        const char *stored_username = getClientUsername(ci->id);
        if (stored_username != NULL) {
            // Make a copy of the username before we remove it from the hash
            temp_username = strdup(stored_username);
            if (temp_username != NULL) {
                username = temp_username;
            } else {
                ValkeyModule_Log(ctx, "warning", "Failed to allocate memory for username during disconnection");
                username = "memory-error";
            }
        } else {
            username = "unknown"; // Fallback if not found in hash
        }
        
        // Client disconnected - remove from hash table
        removeClientUsername(ci->id);
    }
    
    // Format the audit message with username information
    snprintf(buffer, sizeof(buffer), 
             "Client %s event for client #%llu %s:%d using username: %s type %s",
             event_type, 
             (unsigned long long)ci->id, 
             ci->addr, 
             ci->port, 
             username,
             getClientTypeStr(ci)
            );
    
    // Log the message
    logAuditEvent("CONNECTION", event_type, buffer);
    
    // Clean up our temporary memory
    if (temp_username != NULL) {
        free(temp_username);
    }
}

int authLoggerCallback(ValkeyModuleCtx *ctx, ValkeyModuleString *username, 
    ValkeyModuleString *password, ValkeyModuleString **err) {

    VALKEYMODULE_NOT_USED(password);
    VALKEYMODULE_NOT_USED(err);

    if (config.enabled!=1) return VALKEYMODULE_AUTH_NOT_HANDLED;

    // Extract username
    size_t username_len;
    const char *username_str = ValkeyModule_StringPtrLen(username, &username_len);

    // Get client information
    uint64_t client_id = ValkeyModule_GetClientId(ctx);
    char client_info[256] = "unknown";

    // Try to get client info if available
    ValkeyModuleClientInfo client = VALKEYMODULE_CLIENTINFO_INITIALIZER_V1;
    if (ValkeyModule_GetClientInfoById( &client_id, client_id) == VALKEYMODULE_OK) {
        snprintf(client_info, sizeof(client_info), "%s:%d", client.addr, client.port);
    }

    // Format audit message for auth attempt
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), 
                "Authentication attempt for username: %s from client #%llu (%s)",
                 username_str, (unsigned long long)client_id, client_info);

    // Log the auth attempt
    logAuditEvent("AUTH", "ATTEMPT", buffer);

    // Update the username in our hash table if the auth will succeed
    // We don't know yet if it will succeed, but we store it anyway and let
    // the normal AUTH mechanism decide
    // First check if username is in the excluded list and store
    int no_audit = isUsernameExcluded(username_str);
    storeClientUsername(client_id, username_str, no_audit);

    // We're just logging, not making auth decisions, so pass through
    return VALKEYMODULE_AUTH_NOT_HANDLED;
}

void commandLoggerCallback(ValkeyModuleCommandFilterCtx *filter) {
    if (config.enabled!=1) return;

    // Get client info
    unsigned long long client = ValkeyModule_CommandFilterGetClientId(filter);
    int no_audit = 0;
    char *username = "default";
    ClientUsernameEntry *entry = getClientEntry(client);

    // Check if this user is excluded from being audited
    if (entry != NULL) {
        // Get the no_audit flag directly from the stored entry
        no_audit = entry->no_audit;
        username = entry->username;
    }
    if (no_audit) return;  

    // Get command name (first argument)
    size_t cmd_len;
    const ValkeyModuleString *cmd_arg = ValkeyModule_CommandFilterArgGet(filter, 0);
    if (cmd_arg == NULL) return; // No command to audit
    
    const char *cmd_str = ValkeyModule_StringPtrLen(cmd_arg, &cmd_len);
    
    // Skip auditing for audit module commands to avoid recursion
    if (strncasecmp(cmd_str, "audit", 5) == 0) {
        return;
    }
    
    // Determine command category
    int category_match = 0;
    int is_config_cmd = 0;
    int is_key_cmd = 0;
    int is_auth_cmd = 0;
    
    // Check if it's a CONFIG command
    if (strcasecmp(cmd_str, "config") == 0) {
        is_config_cmd = 1;
        // Only audit CONFIG if enabled
        if (config.event_mask & EVENT_CONFIG) {
            category_match = 1;
        }
    }
    // Check if it's an AUTH command
    else if (strcasecmp(cmd_str, "auth") == 0) {
        is_auth_cmd = 1;
        // Only audit AUTH if enabled
        if (config.event_mask & EVENT_AUTH) {
            category_match = 1;
        }
    } else {
        // Check if it's a key command by getting command info
        AuditModuleCommandInfo *cmd_info = ValkeyModule_GetCommandInfo(cmd_str, cmd_len);
        if (cmd_info != NULL) {
            // If command affects keys and key auditing is enabled
            if ((cmd_info->firstkey != 0 || cmd_info->lastkey != 0) && 
                (config.event_mask & EVENT_KEYS)) {
                is_key_cmd = 1;
                category_match = 1;
            }
        }
    }
    
    // Skip if command category doesn't match any enabled audit categories
    if (!category_match) {
        return;
    }
    
    // Build command details including args
    char command_str[256] = "";
    strncpy(command_str, cmd_str, sizeof(command_str) - 1);
    command_str[sizeof(command_str) - 1] = '\0';
    
    // Build details buffer
    char details[2048] = "";
    char client_info[128] = "";
    char username_info[128] = "";
    
    // Add client ID to details
    if (client) {
        snprintf(client_info, sizeof(client_info), "client_id=%llu", client);
        strncat(details, client_info, sizeof(details) - strlen(details) - 1);
    }
    if (username) {
        snprintf(username_info, sizeof(username_info), " username=%s", username);
        strncat(details, username_info, sizeof(details) - strlen(details) - 1);
    }
    
    // For CONFIG commands, add the subcommand and parameter
    if (is_config_cmd) {
        const ValkeyModuleString *subcmd_arg = ValkeyModule_CommandFilterArgGet(filter, 1);
        if (subcmd_arg != NULL) {
            size_t subcmd_len;
            const char *subcmd_str = ValkeyModule_StringPtrLen(subcmd_arg, &subcmd_len);
            
            if (strlen(details) > 0) {
                strncat(details, " ", sizeof(details) - strlen(details) - 1);
            }
            strncat(details, "subcommand=", sizeof(details) - strlen(details) - 1);
            strncat(details, subcmd_str, sizeof(details) - strlen(details) - 1);
            
            // Get parameter for GET/SET subcmd
            if ((strcasecmp(subcmd_str, "get") == 0 || strcasecmp(subcmd_str, "set") == 0)) {
                const ValkeyModuleString *param_arg = ValkeyModule_CommandFilterArgGet(filter, 2);
                if (param_arg != NULL) {
                    size_t param_len;
                    const char *param_str = ValkeyModule_StringPtrLen(param_arg, &param_len);
                    
                    strncat(details, " param=", sizeof(details) - strlen(details) - 1);
                    strncat(details, param_str, sizeof(details) - strlen(details) - 1);
                }
            }
        }
    }
    // For AUTH commands, add redacted password
    else if (is_auth_cmd) {
        if (strlen(details) > 0) {
            strncat(details, " ", sizeof(details) - strlen(details) - 1);
        }
        strncat(details, "password=<REDACTED>", sizeof(details) - strlen(details) - 1);
    }
    // For KEY commands, add key name and optionally payload
    else if (is_key_cmd) {
        AuditModuleCommandInfo *cmd_info = ValkeyModule_GetCommandInfo(cmd_str, cmd_len);
        
        // Add key name if available
        if (cmd_info && cmd_info->firstkey > 0) {
            int key_idx = cmd_info->firstkey;
            const ValkeyModuleString *key_arg = ValkeyModule_CommandFilterArgGet(filter, key_idx);
            
            if (key_arg != NULL) {
                size_t key_len;
                const char *key_str = ValkeyModule_StringPtrLen(key_arg, &key_len);
                
                if (strlen(details) > 0) {
                    strncat(details, " ", sizeof(details) - strlen(details) - 1);
                }
                strncat(details, "key=", sizeof(details) - strlen(details) - 1);
                strncat(details, key_str, sizeof(details) - strlen(details) - 1);
            }
        }
        
        // Include payload if enabled
        if (!config.disable_payload) {
            // Look for potential payload after the key
            int payload_idx = cmd_info && cmd_info->firstkey > 0 ? cmd_info->firstkey + 1 : 1;
            const ValkeyModuleString *payload_arg = ValkeyModule_CommandFilterArgGet(filter, payload_idx);
            
            if (payload_arg != NULL) {
                size_t payload_len;
                const char *payload_str = ValkeyModule_StringPtrLen(payload_arg, &payload_len);
                
                // Limit payload size if configured
                if (payload_len > config.max_payload_size) {
                    payload_len = config.max_payload_size;
                }
                
                if (payload_len > 0) {
                    if (strlen(details) > 0) {
                        strncat(details, " ", sizeof(details) - strlen(details) - 1);
                    }
                    strncat(details, "payload=", sizeof(details) - strlen(details) - 1);
                    
                    // Copy payload up to max length
                    size_t remaining = sizeof(details) - strlen(details) - 1;
                    size_t copy_len = payload_len < remaining ? payload_len : remaining;
                    strncat(details, payload_str, copy_len);
                    
                    // Indicate truncation if needed
                    if (payload_len > config.max_payload_size) {
                        strncat(details, "... (truncated)", sizeof(details) - strlen(details) - 1);
                    }
                }
            }
        }
    }
    
    // Determine category string for the log
    const char *category_str;
    if (is_config_cmd) {
        category_str = "CONFIG";
    } else if (is_auth_cmd) {
        category_str = "AUTH";
    } else if (is_key_cmd) {
        category_str = "KEY_OP";
    } else {
        category_str = "COMMAND";
    }
    
    // Log the audit event
    logAuditEvent(category_str, command_str, details);
}

/////  Module init and shutdown  /////
static int initAuditModule(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    // Set default file path
    config.file_path = strdup("/var/log/valkey/audit.log");
    
    // Process module arguments if any
    for (int i = 0; i < argc; i++) {
        size_t arglen;
        const char *arg = ValkeyModule_StringPtrLen(argv[i], &arglen);
        
        // Handle protocol argument
        if (i < argc-1 && strcasecmp(arg, "protocol") == 0) {
            const char *protocol = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            if (strcasecmp(protocol, "file") == 0) {
                config.protocol = PROTOCOL_FILE;
            } else if (strcasecmp(protocol, "syslog") == 0) {
                config.protocol = PROTOCOL_SYSLOG;
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown protocol '%s', using default", protocol);
            }
        }
        // Handle logfile argument
        else if (i < argc-1 && strcasecmp(arg, "logfile") == 0) {
            const char *logfile = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            if (config.file_path) {
                free(config.file_path);
            }
            config.file_path = strdup(logfile);
        }
        // Handle format argument
        else if (i < argc-1 && strcasecmp(arg, "format") == 0) {
            const char *format = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            if (strcasecmp(format, "text") == 0) {
                config.format = FORMAT_TEXT;
            } else if (strcasecmp(format, "json") == 0) {
                config.format = FORMAT_JSON;
            } else if (strcasecmp(format, "csv") == 0) {
                config.format = FORMAT_CSV;
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown format '%s', using default", format);
            }
        }
        // Handle syslog facility argument
        else if (i < argc-1 && strcasecmp(arg, "syslog-facility") == 0) {
            const char *facility = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            if (strcasecmp(facility, "local0") == 0) config.syslog_facility = LOG_LOCAL0;
            else if (strcasecmp(facility, "local1") == 0) config.syslog_facility = LOG_LOCAL1;
            else if (strcasecmp(facility, "local2") == 0) config.syslog_facility = LOG_LOCAL2;
            else if (strcasecmp(facility, "local3") == 0) config.syslog_facility = LOG_LOCAL3;
            else if (strcasecmp(facility, "local4") == 0) config.syslog_facility = LOG_LOCAL4;
            else if (strcasecmp(facility, "local5") == 0) config.syslog_facility = LOG_LOCAL5;
            else if (strcasecmp(facility, "local6") == 0) config.syslog_facility = LOG_LOCAL6;
            else if (strcasecmp(facility, "local7") == 0) config.syslog_facility = LOG_LOCAL7;
            else if (strcasecmp(facility, "user") == 0) config.syslog_facility = LOG_USER;
            else if (strcasecmp(facility, "daemon") == 0) config.syslog_facility = LOG_DAEMON;
            else {
                ValkeyModule_Log(ctx, "warning", "Unknown syslog facility '%s', using default", facility);
            }
        }
        // Handle events argument
        else if (i < argc-1 && strcasecmp(arg, "events") == 0) {
            const char *events = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            // Parse comma-separated event list
            config.event_mask = 0;  // Reset events
            
            char *events_copy = strdup(events);
            char *token = strtok(events_copy, ",");
            
            while (token != NULL) {
                if (strcasecmp(token, "connections") == 0) {
                    config.event_mask |= EVENT_CONNECTIONS;
                } else if (strcasecmp(token, "auth") == 0) {
                    config.event_mask |= EVENT_AUTH;
                } else if (strcasecmp(token, "config") == 0) {
                    config.event_mask |= EVENT_CONFIG;
                } else if (strcasecmp(token, "keys") == 0) {
                    config.event_mask |= EVENT_KEYS;
                } else if (strcasecmp(token, "all") == 0) {
                    config.event_mask = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS;
                } else if (strcasecmp(token, "none") == 0) {
                    config.event_mask = 0;
                } else {
                    ValkeyModule_Log(ctx, "warning", "Unknown event type '%s', ignoring", token);
                }
                
                token = strtok(NULL, ",");
            }
            
            free(events_copy);
        }
        // Handle disable-payload argument
        else if (strcasecmp(arg, "disable-payload") == 0) {
            config.disable_payload = 1;
        }
        // Handle max-payload-size argument
        else if (i < argc-1 && strcasecmp(arg, "max-payload-size") == 0) {
            const char *size_str = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            char *endptr;
            long size = strtol(size_str, &endptr, 10);
            
            if (*endptr != '\0' || size < 0) {
                ValkeyModule_Log(ctx, "warning", "Invalid payload size '%s', using default", size_str);
            } else {
                config.max_payload_size = (size_t)size;
            }
        }
    }
    
    // Open log file if using file protocol
    if (config.protocol == PROTOCOL_FILE && config.file_path) {
        config.file_fd = open(config.file_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (config.file_fd == -1) {
            ValkeyModule_Log(ctx, "warning", "Failed to open audit log file: %s", config.file_path);
            return VALKEYMODULE_ERR;
        }
    }
    
    // Initialize syslog if using syslog protocol
    if (config.protocol == PROTOCOL_SYSLOG) {
        openlog("valkey-audit", LOG_PID, config.syslog_facility);
    }
    
    return VALKEYMODULE_OK;
}

// Register the commands, connection callback and command filter functions
int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (ValkeyModule_Init(ctx,"audit",1,VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) 
        return VALKEYMODULE_ERR;

    // Initialize the audit module with passed arguments
    if (initAuditModule(ctx, argv, argc) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }  
    
    // Initialize stats
    stats.start_time = time(NULL);

    // Initialize hash table for client usernames
    for (int i = 0; i < USERNAME_HASH_SIZE; i++) {
        username_hash[i] = NULL;
    }

    // Register module configurations
    if (ValkeyModule_RegisterStringConfig(ctx, "protocol", "file audit.log", 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditProtocol, setAuditProtocol, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterStringConfig(ctx, "format", "json", 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditFormat, setAuditFormat, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterStringConfig(ctx, "events", "all", 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditEvents, setAuditEvents, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterBoolConfig(ctx, "payload_disable", 0, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditPayloadDisable, setAuditPayloadDisable, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterNumericConfig(ctx, "payload_maxsize", 1024,  // Default 1024
           VALKEYMODULE_CONFIG_DEFAULT,
           0,            // Minimum value
           LLONG_MAX,    // Maximum value
           getAuditPayloadMaxSize, setAuditPayloadMaxSize, 
           NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterStringConfig(ctx, "excludeusers", "", 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditExcludeUsers, setAuditExcludeUsers, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Boolean config example
    if (ValkeyModule_RegisterBoolConfig(ctx, "enabled", 1, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditEnabled, setAuditEnabled, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Load all configurations
    if (ValkeyModule_LoadConfigs(ctx) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

        // Register the AUDITUSERS command separately (keeping it as a top-level command)
    if (ValkeyModule_CreateCommand(ctx, "auditusers", 
            AuditUsersCommand,
            "admin no-cluster", 0, 0, 0) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register audit.getconfig command
    if (ValkeyModule_CreateCommand(ctx, "audit.getconfig",
            auditGetConfig_ValkeyCommand,
            "admin readonly", 0, 0, 0) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Subscribe to client connection/disconnection events
    if (ValkeyModule_SubscribeToServerEvent(ctx,
        ValkeyModuleEvent_ClientChange, clientChangeCallback) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    // Register the auth callback
    ValkeyModule_RegisterAuthCallback(ctx, authLoggerCallback);

    // Register our command filter callback
    if ((filter = ValkeyModule_RegisterCommandFilter(ctx, commandLoggerCallback, 
        VALKEYMODULE_CMDFILTER_NOSELF))== NULL) 
        return VALKEYMODULE_ERR;    

    return VALKEYMODULE_OK;

}

// Module cleanup on unload
int ValkeyModule_OnUnload(ValkeyModuleCtx *ctx) {
    VALKEYMODULE_NOT_USED(ctx);
    
    // Close file descriptor if open
    if (config.file_fd != -1) {
        close(config.file_fd);
        config.file_fd = -1;
    }
    
    // Close syslog if it was in use
    if (config.protocol == PROTOCOL_SYSLOG) {
        closelog();
    }
    
    // Free allocated memory
    if (config.file_path) {
        free(config.file_path);
        config.file_path = NULL;
    }
    
    return VALKEYMODULE_OK;
}