#include "valkeymodule.h"
#include "module.h"
#include "version.h"
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

static ValkeyModuleCommandFilter *filter;
static ConnectionStats stats = {0};
static ClientUsernameEntry *username_hash[USERNAME_HASH_SIZE] = {0};

// Global head of the linked list for excluded usernames
static ExclusionRule *exclusion_rules_head = NULL;

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

// Static definition of command info cache 
static AuditModuleCommandInfo *last_cmd_info = NULL;
static char last_cmd_name[64] = "";
static size_t last_cmd_len = 0;

// Static command info table (hash table)
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

// helper functions for IP validation
int isValidIPv4(const char *ip) {
    if (ip == NULL || *ip == '\0') return 0;
    
    // IPv4 address must be in format x.x.x.x where x is 0-255
    unsigned int a, b, c, d;
    char extra; // To detect any extra characters
    
    int result = sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra);
    
    // Check if we got exactly 4 numbers and nothing else
    if (result != 4) return 0;
    
    // Check if each number is in range 0-255
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    
    return 1;
}

int isValidIPv6(const char *ip) {
    if (ip == NULL || *ip == '\0') return 0;
    
    // Basic validation for IPv6
    // More comprehensive validation would check for proper formatting
    // of hexadecimal groups and compressed notation
    
    // Check for presence of colons (at least 2 for IPv6)
    int colons = 0;
    const char *ptr = ip;
    while (*ptr) {
        if (*ptr == ':') colons++;
        // IPv6 only allows hexadecimal digits and colons
        else if (!((*ptr >= '0' && *ptr <= '9') || 
                  (*ptr >= 'a' && *ptr <= 'f') || 
                  (*ptr >= 'A' && *ptr <= 'F'))) {
            return 0;
        }
        ptr++;
    }
    
    // IPv6 needs at least 2 colons
    if (colons < 2) return 0;
    
    return 1;
}

int isValidIP(const char *ip) {
    if (ip == NULL || *ip == '\0') return 0;
    
    // Check for IPv4
    if (isValidIPv4(ip)) return 1;
    
    // Check for IPv6
    if (isValidIPv6(ip)) return 1;
    
    return 0;
}

AuditModuleCommandInfo* ValkeyModule_GetCommandInfo(const char *cmd_name, size_t cmd_len) {
    if (cmd_name == NULL || cmd_len == 0) {
        return NULL;
    }

    // Check if we can return the cached command info
    if (last_cmd_info != NULL &&
        last_cmd_len == cmd_len &&
        strncasecmp(last_cmd_name, cmd_name, cmd_len) == 0) {
        return last_cmd_info;
    }

    // Initialize the command table if not already done
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

    // Lookup the command in the hash table
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

    // Command not found
    return NULL;
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

static void formatEventText(char *buffer, size_t size, const char *category, const char *command, const char *details, const char *username, const char *ipaddr) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(buffer, size, "[%s] [%s] %s %s %s %s", 
             timestamp, category, command, username, ipaddr, details ? details : "");
}

static void formatEventJson(char *buffer, size_t size, const char *category, const char *command, const char *details, const char *username, const char *ipaddr) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(buffer, size,
        "{\"timestamp\":\"%s\",\"category\":\"%s\",\"command\":\"%s\",\"username\":\"%s\",\"ip\":\"%s\",\"details\":\"%s\"}",
        timestamp, category, command, username, ipaddr, details ? details : "null");
}

static void formatEventCsv(char *buffer, size_t size, const char *category, const char *command, const char *details, const char *username, const char *ipaddr) {
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
    
    snprintf(buffer, size, "%s,%s,%s,%s,%s,%s", 
             timestamp, category, command, username, ipaddr, escaped_details);
}

static void logAuditEvent(const char *category, const char *command, const char *details, const char *username, const char *ipaddr) {
    char buffer[4096];
    
    switch(config.format) {
        case FORMAT_JSON:
            formatEventJson(buffer, sizeof(buffer), category, command, details, username, ipaddr);
            break;
        case FORMAT_CSV:
            formatEventCsv(buffer, sizeof(buffer), category, command, details, username, ipaddr);
            break;
        case FORMAT_TEXT:
        default:
            formatEventText(buffer, sizeof(buffer), category, command, details, username, ipaddr);
            break;
    }
    
    writeAuditLog("%s", buffer);
}


/////   Section for exclusion rules functions  /////
// Free the entire exclusion rules list
void freeExclusionRules() {
    ExclusionRule *current = exclusion_rules_head;
    while (current != NULL) {
        ExclusionRule *next = current->next;
        if (current->username) free(current->username);
        if (current->ip_address) free(current->ip_address);
        free(current);
        current = next;
    }
    exclusion_rules_head = NULL;
}

int isRuleAlreadyExcluded(const char *username, const char *ip_address) {
    ExclusionRule *current = exclusion_rules_head;
    while (current != NULL) {
        // Check if this rule matches
        int username_match = (username == NULL && current->username == NULL) ||
                            (username != NULL && current->username != NULL && 
                             strcasecmp(current->username, username) == 0);
        
        int ip_match = (ip_address == NULL && current->ip_address == NULL) ||
                       (ip_address != NULL && current->ip_address != NULL && 
                        strcmp(current->ip_address, ip_address) == 0);
        
        if (username_match && ip_match) {
            return 1;  // Found a match
        }
        
        current = current->next;
    }
    return 0;  // No match found
}

void addExclusionRule(const char *username, const char *ip_address) {
    // Skip if both are NULL (shouldn't happen)
    if (username == NULL && ip_address == NULL) return;
    
    // IP address must be valid if provided
    if (ip_address != NULL && !isValidIP(ip_address)) return;
    
    // Check for duplicate rule
    if (isRuleAlreadyExcluded(username, ip_address)) return;
    
    ExclusionRule *new_rule = (ExclusionRule*)malloc(sizeof(ExclusionRule));
    if (new_rule == NULL) return;  // Out of memory
    
    // Initialize fields
    new_rule->username = username ? strdup(username) : NULL;
    new_rule->ip_address = ip_address ? strdup(ip_address) : NULL;
    
    // Check for memory allocation failures
    if ((username && new_rule->username == NULL) || 
        (ip_address && new_rule->ip_address == NULL)) {
        if (new_rule->username) free(new_rule->username);
        if (new_rule->ip_address) free(new_rule->ip_address);
        free(new_rule);
        return;  // Out of memory
    }
    
    // Add at the beginning of the list
    new_rule->next = exclusion_rules_head;
    exclusion_rules_head = new_rule;
    
    // Log the added rule
    char log_message[256];
    if (username && ip_address) {
        snprintf(log_message, sizeof(log_message), 
                "Added exclusion rule: username=%s, ip=%s", username, ip_address);
    } else if (username) {
        snprintf(log_message, sizeof(log_message), 
                "Added exclusion rule: username=%s (any IP)", username);
    } else {
        snprintf(log_message, sizeof(log_message), 
                "Added exclusion rule: ip=%s (any username)", ip_address);
    }
    logAuditEvent("AUDIT", "ADD_EXCLUSION_RULE", log_message, "n/a", "n/a");
}

int isClientExcluded(const char *username, const char *ip_address) {
    if (username == NULL && ip_address == NULL) {
        return 0;  // No username or IP - can't match
    }

    ExclusionRule *current = exclusion_rules_head;
    while (current != NULL) {
        // Check if this rule applies to the client

        // Case 1: Rule is username-only (no IP specified in rule)
        if (current->username != NULL && current->ip_address == NULL) {
            // Check if username matches
            if (username != NULL && strcasecmp(current->username, username) == 0) {
                return 1;  // Client should be excluded from audit
            }
        }

        // Case 2: Rule is IP-only (no username specified in rule)
        else if (current->username == NULL && current->ip_address != NULL) {
            // Check if IP matches
            if (ip_address != NULL && strcmp(current->ip_address, ip_address) == 0) {
                return 1;  // Client should be excluded from audit
            }
        }

        // Case 3: Rule is both username and IP
        else if (current->username != NULL && current->ip_address != NULL) {
            // Both username AND IP must match
            if (username != NULL && ip_address != NULL && 
                strcasecmp(current->username, username) == 0 && 
                strcmp(current->ip_address, ip_address) == 0) {
                return 1;  // Client should be excluded from audit
            }
        }

        current = current->next;
    }

    return 0;  // No matching rule found
}

int isUsernameExcluded(const char *username) {
    if (username == NULL) {
        return 0;
    }
    
    return isClientExcluded(username, NULL);
}

int isIPExcluded(const char *ip_address) {
    if (ip_address == NULL) {
        return 0;
    }
    
    return isClientExcluded(NULL, ip_address);
}

void updateNoAuditFlags() {
    // Update the no_audit flag for all clients based on current rules
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; ++i) {
        ClientUsernameEntry *current = username_hash[i];
        while (current != NULL) {
            // Check if this client matches any exclusion rule
            current->no_audit = isClientExcluded(current->username, current->ip_address);
            current = current->next;
        }
    }
}

// Parse the comma-separated rules input and update the exclusion rules list
void updateExclusionRules(const char *csv_list) {
    // First, reset all no_audit flags in the client hash table
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; ++i) {
        ClientUsernameEntry *current = username_hash[i];
        while (current != NULL) {
            current->no_audit = 0;
            current = current->next;
        }
    }
    
    // Clear previous entries in the excluded list
    freeExclusionRules();

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

        // Check if not empty
        if (*token != '\0') {
            char *username = NULL;
            char *ip_address = NULL;
            
            // Parse the rule format "username@ip" or just "username" or "@ip"
            char *at_sign = strchr(token, '@');
            if (at_sign != NULL) {
                // We have "@" - split into username and IP parts
                *at_sign = '\0'; // Split the string
                
                // Handle username part (left of @)
                if (at_sign > token) { // There's something before @
                    username = token;
                }
                
                // Handle IP part (right of @)
                if (*(at_sign + 1) != '\0') { // There's something after @
                    ip_address = at_sign + 1;
                    
                    // Validate the IP address
                    if (!isValidIP(ip_address)) {
                        // Log invalid IP but continue processing other rules
                        char log_message[256];
                        snprintf(log_message, sizeof(log_message), 
                                "Invalid IP address in exclusion rule: %s", ip_address);
                        logAuditEvent("AUDIT", "INVALID_IP_ADDRESS", log_message, "n/a", "n/a");
                        
                        // Skip this rule
                        token = strtok(NULL, ",");
                        continue;
                    }
                }
            } else {
                // No @ sign, treat as username only
                username = token;
            }
            
            // Add to exclusion rules if at least one part is specified
            if (username != NULL || ip_address != NULL) {
                addExclusionRule(username, ip_address);
                
                // Update no_audit flags for matching clients
                updateNoAuditFlags();
            }
        }

        token = strtok(NULL, ",");
    }

    free(list_copy);
}


/////   Section for client hash table functions  /////
// Find the entry for client_id in the clients hash table
// Helper function to get client entry from hash table
ClientUsernameEntry* getClientEntry(uint64_t client_id) {
    // Get hash index
    unsigned int hash_index = client_id % USERNAME_HASH_SIZE;
    
    // Search for the client in the linked list
    ClientUsernameEntry *entry = username_hash[hash_index];
    while (entry != NULL) {
        if (entry->client_id == client_id) {
            return entry;
        }
        entry = entry->next;
    }
    
    // Not found
    return NULL;
}

// For backward compatibility if needed
const char* getClientUsername(uint64_t client_id) {
    ClientUsernameEntry *entry = getClientEntry(client_id);
    if (entry != NULL) {
        return entry->username;
    }
    return NULL;
}

// New helper function to get client IP address
const char* getClientIPAddress(uint64_t client_id) {
    ClientUsernameEntry *entry = getClientEntry(client_id);
    if (entry != NULL && entry->ip_address != NULL) {
        return entry->ip_address;
    }
    return NULL;
}

// Add or update a client ID to username mapping
// also set the no_audit flag if the username is to be excluded
void storeClientInfo(uint64_t client_id, const char *username, const char *ip_address, int no_audit) {
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
    
    // Make a copy of the IP address
    char *ip_copy = NULL;
    if (ip_address != NULL) {
        ip_copy = strdup(ip_address);
        if (ip_copy == NULL) {
            // Handle strdup failure for IP
            free(username_copy);
            free(entry);
            return;
        }
    }
    
    // Initialize the entry
    entry->client_id = client_id;
    entry->username = username_copy;
    entry->ip_address = ip_copy;
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
                
                // Update IP address
                if (current->ip_address != NULL) {
                    free(current->ip_address);
                }
                current->ip_address = ip_copy;
                
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
void removeClientInfo(uint64_t client_id) {
    // Get hash index
    unsigned int hash_index = client_id % USERNAME_HASH_SIZE;
    
    ClientUsernameEntry *entry = username_hash[hash_index];
    ClientUsernameEntry *prev = NULL;
    
    while (entry) {
        if (entry->client_id == client_id) {
            // Found the entry to remove
            if (prev) {
                prev->next = entry->next;
            } else {
                username_hash[hash_index] = entry->next;
            }
            
            // Free memory
            free(entry->username);
            if (entry->ip_address != NULL) {
                free(entry->ip_address);
            }
            free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

// Initialize hash table
void initClientInfoHashTable() {
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; i++) {
        username_hash[i] = NULL;
    }
}

// Clean up hash table memory when shutting down
void cleanupClientInfoHashTable() {
    for (unsigned int i = 0; i < USERNAME_HASH_SIZE; i++) {
        ClientUsernameEntry *current = username_hash[i];
        while (current != NULL) {
            ClientUsernameEntry *next = current->next;
            free(current->username);
            if (current->ip_address != NULL) {
                free(current->ip_address);
            }
            free(current);
            current = next;
        }
        username_hash[i] = NULL;
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
                                  "Client ID: %llu, Username: %s, IP: %s, NoAudit: %d \n", 
                                  (unsigned long long)entry->client_id, 
                                  entry->username ? entry->username : "NULL",
                                  entry->ip_address,
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

// Get client type string
static const char* getClientTypeStr(ValkeyModuleClientInfo *ci) {
    if (ci->flags & (1ULL << 0)) return "normal";
    if (ci->flags & (1ULL << 1)) return "replica";
    if (ci->flags & (1ULL << 2)) return "pubsub";
    return "unknown";
}

/////  Module config  /////
// Protocol
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

// Format
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

int setAuditFormat(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    size_t len;
    const char *format = ValkeyModule_StringPtrLen(new_val, &len);
    
    if (strcasecmp(format, "text") == 0) {
        config.format = FORMAT_TEXT;
        logAuditEvent("AUDIT", "SET_FORMAT", "format=text", "n/a", "n/a");
        return VALKEYMODULE_OK;
    } else if (strcasecmp(format, "json") == 0) {
        config.format = FORMAT_JSON;
        logAuditEvent("AUDIT", "SET_FORMAT", "format=json", "n/a", "n/a");
        return VALKEYMODULE_OK;
    } else if (strcasecmp(format, "csv") == 0) {
        config.format = FORMAT_CSV;
        logAuditEvent("AUDIT", "SET_FORMAT", "format=csv", "n/a", "n/a");
        return VALKEYMODULE_OK;
    } else {
        // Create error message
        *err = ValkeyModule_CreateString(NULL, "ERR Unknown format. Use 'text', 'json', or 'csv'", 48);
        return VALKEYMODULE_ERR;
    }
}

// Events
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
        logAuditEvent("AUDIT", "SET_EVENTS", "events=all", "n/a", "n/a");
        ValkeyModule_Free(events_copy);
        return VALKEYMODULE_OK;
    } else if (strcasecmp(events_copy, "none") == 0) {
        config.event_mask = 0;
        logAuditEvent("AUDIT", "SET_EVENTS", "events=none", "n/a", "n/a");
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
    logAuditEvent("AUDIT", "SET_EVENTS", details, "n/a", "n/a");
    
    ValkeyModule_Free(events_copy);
    return VALKEYMODULE_OK;
}

// Payload
int getAuditPayloadDisable(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    return config.disable_payload;
}

int setAuditPayloadDisable(const char *name, int new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);
    config.disable_payload = new_val;
    
    char details[32];
    snprintf(details, sizeof(details), "disable=%s", new_val ? "yes" : "no");
    logAuditEvent("AUDIT", "SET_PAYLOAD_OPTIONS", details, "n/a", "n/a");
    
    return VALKEYMODULE_OK;
}

long long getAuditPayloadMaxSize(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    return config.max_payload_size;
}

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
    logAuditEvent("AUDIT", "SET_PAYLOAD_OPTIONS", details, "n/a", "n/a");
    
    return VALKEYMODULE_OK;
}

// Enabled
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

// Config cmd auditing enabled
int getAuditAlwaysAuditConfig(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    return config.always_audit_config;
}

int setAuditAlwaysAuditConfig(const char *name, int new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);
    config.always_audit_config = new_val;
    return VALKEYMODULE_OK;   
}

// Exclusion
ValkeyModuleString *getAuditExclusionRules(const char *name, void *privdata) {
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
    ExclusionRule *current = exclusion_rules_head;
    
    while (current != NULL) {
        // Calculate the length needed for this rule entry
        size_t username_len = current->username ? strlen(current->username) : 0;
        size_t ip_len = current->ip_address ? strlen(current->ip_address) : 0;
        size_t entry_len = username_len + ip_len + 2; // +2 for potential @ and comma
        size_t current_len = strlen(buffer);
        
        // Check if we need to resize the buffer
        if (current_len + entry_len + 1 >= bufsize) {
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
        
        // Add the rule in format "username@ip" or just "username" or "@ip"
        if (current->username) {
            strcat(buffer, current->username);
        }
        
        if (current->ip_address) {
            strcat(buffer, "@");
            strcat(buffer, current->ip_address);
        } else if (!current->username) {
            // Edge case: if both are NULL (shouldn't happen)
            strcat(buffer, "@");
        }
        
        current = current->next;
    }
    
    ValkeyModuleString *result = ValkeyModule_CreateString(NULL, buffer, strlen(buffer));
    free(buffer);
    
    return result;
}

int setAuditExclusionRules(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);

    
    size_t len;
    const char *new_list = ValkeyModule_StringPtrLen(new_val, &len);
    
    // Update the exclusion rules
    updateExclusionRules(new_list);
    
    // Log the event with truncation for very long lists
    char details[200];
    if (len < 180) {
        snprintf(details, sizeof(details), "excluderules=%s", new_list);
    } else {
        // Truncate long lists in the log
        char truncated[180];
        strncpy(truncated, new_list, 176);
        truncated[176] = '\0';
        strcat(truncated, "...");
        snprintf(details, sizeof(details), "excluderules=%s", truncated);
    }
    logAuditEvent("AUDIT", "SET_EXCLUDE_RULES", details, "n/a", "n/a");
    
    return VALKEYMODULE_OK;
}

// Clear all exclusion rules - to be used when the configuration is set to empty
int clearAuditExclusionRules(const char *name, void *privdata) {
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
    
    // Free all exclusion rules
    freeExclusionRules();
    
    // Log the event
    logAuditEvent("AUDIT", "CLEAR_EXCLUDE_RULES", "", "n/a", "n/a");
    
    return VALKEYMODULE_OK;
}


/////  Callback functions  /////
// Client state change callback, used for connection auditing
void clientChangeCallback(ValkeyModuleCtx *ctx, ValkeyModuleEvent e, uint64_t sub, void *data) {
    VALKEYMODULE_NOT_USED(e);

    if ((config.enabled!=1) || !(config.event_mask & EVENT_CONNECTIONS)) return;

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

            // Check if client should be excluded from audit based on username and IP
            int no_audit = isClientExcluded(username, ci->addr);
            
            // Store username and IP in hash table - storeClientUsername makes its own copies
            storeClientInfo(ci->id, username, ci->addr, no_audit);

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

            // Store placeholder in hash table with IP address
            storeClientInfo(ci->id, username, ci->addr, 0);
        }
    } else if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED) {
        // For disconnection, get the client info from the hash table
        ClientUsernameEntry *entry = getClientEntry(ci->id);
        if (entry != NULL) {
            // Make a copy of the username before we remove it from the hash
            if (entry->username != NULL) {
                temp_username = strdup(entry->username);
                if (temp_username != NULL) {
                    username = temp_username;
                } else {
                    ValkeyModule_Log(ctx, "warning", "Failed to allocate memory for username during disconnection");
                    username = "memory-error";
                }
            }
        } else {
            username = "unknown"; // Fallback if not found in hash
        }
        
        // Client disconnected - remove from hash table
        removeClientInfo(ci->id);
    }
    
    // Format the audit message with username information
    snprintf(buffer, sizeof(buffer), 
             "client #%llu %s:%d using username: %s type %s",
             (unsigned long long)ci->id, 
             ci->addr, 
             ci->port, 
             username,
             getClientTypeStr(ci)
            );
    
    // Log the message
    logAuditEvent("CONNECTION", event_type, buffer, username, ci->addr);
    
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
    char client_ip[128] = "unknown"; 

    // Try to get client info if available
    ValkeyModuleClientInfo client = VALKEYMODULE_CLIENTINFO_INITIALIZER_V1;
    if (ValkeyModule_GetClientInfoById(&client, client_id) == VALKEYMODULE_OK) {
        snprintf(client_info, sizeof(client_info), "%s:%d", client.addr, client.port);
        strncpy(client_ip, client.addr, sizeof(client_ip) - 1);
        client_ip[sizeof(client_ip) - 1] = '\0'; // Ensure null termination
    }

    // Format audit message for auth attempt
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), 
                "Authentication attempt for username: %s from client #%llu (%s)",
                 username_str, (unsigned long long)client_id, client_info);

    // Log the auth attempt
    logAuditEvent("AUTH", "ATTEMPT", buffer, username_str, client_ip);

    // Update the username in our hash table if the auth will succeed
    // We don't know yet if it will succeed, but we store it anyway and let
    // the normal AUTH mechanism decide
    // Check if client should be excluded based on username and IP
    int no_audit = isClientExcluded(username_str, client_ip);
    storeClientInfo(client_id, username_str, client_ip, no_audit);

    // We're just logging, not making auth decisions, so pass through
    return VALKEYMODULE_AUTH_NOT_HANDLED;
}

void commandLoggerCallback(ValkeyModuleCommandFilterCtx *filter) {
    if (config.enabled!=1) return;

     // Get command name
    size_t cmd_len; 
    const ValkeyModuleString *cmd_arg = ValkeyModule_CommandFilterArgGet(filter, 0);
    if (cmd_arg == NULL) return; // No command to audit
    
    const char *cmd_str = ValkeyModule_StringPtrLen(cmd_arg, &cmd_len);
    
    // Skip auditing for audit module commands to avoid recursion
    if (strncasecmp(cmd_str, "audit", 5) == 0) {
        return;
    }
    
    // Early check for CONFIG commands with always_audit_config enabled
    int is_config_cmd = strcasecmp(cmd_str, "config") == 0;
    
    // Get client info
    unsigned long long client = ValkeyModule_CommandFilterGetClientId(filter);
    int no_audit = 0;
    char *username = "default";
    char *ip_address = "unknown";
    ClientUsernameEntry *entry = getClientEntry(client);
    
    // Always get client info if available, for logging purposes
    if (entry != NULL) {
        username = entry->username;
        ip_address = entry->ip_address;
        no_audit = entry->no_audit;
    }
    
    // Skip auditing if no_audit is set and it's not a special case:
    //   it's not a CONFIG command with always_audit_config enabled
    if (no_audit) {
        if (!(is_config_cmd && config.always_audit_config))
        {
            return;
        }
    }

    // Determine command category : config command determined early for exclusion
    int category_match = 0;
    int is_key_cmd = 0;
    int is_auth_cmd = 0;
    
    // Check if it's a CONFIG command
    if (is_config_cmd) {
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
    char ip_info[128] = "";
    
    // Add client ID to details
    if (client) {
        snprintf(client_info, sizeof(client_info), "client_id=%llu", client);
        strncat(details, client_info, sizeof(details) - strlen(details) - 1);
    }
    if (username) {
        snprintf(username_info, sizeof(username_info), " username=%s", username);
        strncat(details, username_info, sizeof(details) - strlen(details) - 1);
    }
    if (ip_address) {
        snprintf(ip_info, sizeof(ip_info), " ip=%s", ip_address);
        strncat(details, ip_info, sizeof(details) - strlen(details) - 1);
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
    logAuditEvent(category_str, command_str, details, username, ip_address);
}

// to be removed
// Command handler for the AUDITUSERS command
int AuditUsersCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);
    
    printUserHashContents(ctx);
    
    // Reply to client
    ValkeyModule_ReplyWithSimpleString(ctx, "OK - user hash table dumped to logs");
    
    return VALKEYMODULE_OK;
}

/////  Module init and shutdown  /////
static int initAuditModule(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    // Set default file path
    config.file_path = strdup("/var/log/valkey/audit.log");
    
    // Process module arguments if any
    for (int i = 0; i < argc; i++) {
        size_t arglen;
        const char *arg = ValkeyModule_StringPtrLen(argv[i], &arglen);
        
        // Handle enable argument
        if (i < argc-1 && strcasecmp(arg, "enable") == 0) {
            const char *enabled = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
        
            if (strcasecmp(enabled, "yes") == 0 || strcasecmp(enabled, "1") == 0) {
                config.enabled = 1;
            } else if (strcasecmp(enabled, "no") == 0 || strcasecmp(enabled, "0") == 0) {
                config.enabled = 0;
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown value for enable '%s', using default", enabled);
            }
        }
        // Handle always_audit_config argument 
        if (i < argc-1 && strcasecmp(arg, "always_audit_config") == 0) {
            const char *always_audit_config = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
        
            if (strcasecmp(always_audit_config, "yes") == 0 || strcasecmp(always_audit_config, "1") == 0) {
                config.always_audit_config = 1;
            } else if (strcasecmp(always_audit_config, "no") == 0 ||    strcasecmp(always_audit_config, "0") == 0){
                config.always_audit_config = 0;
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown value for always_audit_config '%s', using default", always_audit_config);
            }
        }
        // Handle protocol argument
        else if (i < argc-1 && strcasecmp(arg, "protocol") == 0) {
            const char *protocol = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the protocol argument since we processed it
            
            if (strcasecmp(protocol, "file") == 0) {
                config.protocol = PROTOCOL_FILE;
                
                // Check if there's another argument available for filepath
                if (i < argc-1) {
                    config.file_path = strdup(ValkeyModule_StringPtrLen(argv[i+1], NULL));
                    i++;  // Skip the filepath argument
                } else {
                    ValkeyModule_Log(ctx, "warning", "Missing filepath for file protocol, using default");
                }
            } else if (strcasecmp(protocol, "syslog") == 0) {
                config.protocol = PROTOCOL_SYSLOG;
                
                // Check if there's another argument available for syslog-facility
                if (i < argc-1) {
                    const char *facility = ValkeyModule_StringPtrLen(argv[i+1], NULL);
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
                    i++;
                } else {
                    ValkeyModule_Log(ctx, "warning", "Missing syslog-facility for syslog protocol, using default");
                }
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown protocol '%s', using default", protocol);
            }
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
        // Handle events argument
        else if (i < argc-1 && strcasecmp(arg, "events") == 0) {
            const char *events = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;

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
        // Handle excluderules argument
        else if (i < argc-1 && strcasecmp(arg, "excluderules") == 0) {
            const char *exclude_rules = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;  // Skip the next argument since we processed it
            
            // Update the exclusion rules
            updateExclusionRules(exclude_rules);
        }
        // Handle disable-payload argument
        else if (strcasecmp(arg, "payload_disable") == 0) {
            config.disable_payload = 1;
        }
        // Handle max-payload-size argument
        else if (i < argc-1 && strcasecmp(arg, "payload_maxsize") == 0) {
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
    if (ValkeyModule_Init(ctx,"audit",VALKEYAUDIT_MODULE_VERSION,VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) 
        return VALKEYMODULE_ERR;
    
    char buffer[128];
    snprintf(buffer, sizeof(buffer), 
                "valkey-audit version: %s",
                VALKEYAUDIT_MODULE_VERSION_STR);
    ValkeyModule_Log(ctx, "notice", "%s", buffer);

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
    char default_protocol[256]; // Adjust buffer size as needed
    snprintf(default_protocol, sizeof(default_protocol), "file %s", config.file_path);
    if (ValkeyModule_RegisterStringConfig(ctx, "protocol", default_protocol, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditProtocol, setAuditProtocol, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    const char* format_strings[] = {
        "text",   // FORMAT_TEXT (0)
        "json",   // FORMAT_JSON (1)
        "csv",    // FORMAT_CSV (2)
    };
    const char* default_format = format_strings[config.format];

    if (ValkeyModule_RegisterStringConfig(ctx, "format", default_format, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditFormat, setAuditFormat, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Create a string representation of the default event mask
    char default_events[256] = "";
    if (config.event_mask & EVENT_CONNECTIONS) {
        strcat(default_events, "connections,");
    }
    if (config.event_mask & EVENT_AUTH) {
        strcat(default_events, "auth,");
    }
    if (config.event_mask & EVENT_CONFIG) {
        strcat(default_events, "config,");
    }
    if (config.event_mask & EVENT_KEYS) {
        strcat(default_events, "keys,");
    }

    // Remove trailing space if any events were added
    if (default_events[0] != '\0') {
        default_events[strlen(default_events)-1] = '\0';
    }

    if (ValkeyModule_RegisterStringConfig(ctx, "events", default_events, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditEvents, setAuditEvents, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterBoolConfig(ctx, "payload_disable", config.disable_payload, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditPayloadDisable, setAuditPayloadDisable, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterNumericConfig(ctx, "payload_maxsize", config.max_payload_size,
           VALKEYMODULE_CONFIG_DEFAULT,
           0,            // Minimum value
           LLONG_MAX,    // Maximum value
           getAuditPayloadMaxSize, setAuditPayloadMaxSize, 
           NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    ValkeyModuleString *initial_rules = getAuditExclusionRules("excluderules", NULL);
    const char *default_val = ValkeyModule_StringPtrLen(initial_rules, NULL);
    if (ValkeyModule_RegisterStringConfig(ctx, "excluderules", default_val, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditExclusionRules, setAuditExclusionRules, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }
    ValkeyModule_FreeString(ctx, initial_rules);

    if (ValkeyModule_RegisterBoolConfig(ctx, "enabled", config.enabled, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditEnabled, setAuditEnabled, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    if (ValkeyModule_RegisterBoolConfig(ctx, "always_audit_config", config.always_audit_config, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditAlwaysAuditConfig, setAuditAlwaysAuditConfig,
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
            "admin", 0, 0, 0) == VALKEYMODULE_ERR) {
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