#define _GNU_SOURCE
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
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
/* for TCP */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

static char server_hostname[HOST_NAME_MAX];
static int loglevel_debug = 0;

static AuditConfig config = {
    .enabled = 1,
    .protocol = PROTOCOL_FILE,
    .format = FORMAT_TEXT,
    .event_mask = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS | EVENT_OTHER,
    .disable_payload = 0,
    .max_payload_size = 1024,
    .file_path = "audit.log",
    .syslog_facility = LOG_LOCAL0,
    .syslog_priority = LOG_NOTICE,
    .fsync_policy = AOF_FSYNC_ALWAYS,
    
    /* Initialize fields that require runtime allocation to NULL/default values */
    .buffer = NULL,
    .buffer_size = 16 * 1024 * 1024,  /* 16MB default */
    .buffer_head = 0,
    .buffer_tail = 0,
    .buffer_used = 0,
    .file_fd = -1,
    .tcp_socket = -1,
    .tcp_connected = 0,
    .tcp_retry_count = 0,
    .worker_running = 0,
    .shutdown_flag = 0
};

/* Forward declarations */
static void *auditLogWorker(void *arg);
static int connectTcp(void);
static int writeToTcp(const char *data, size_t len);
static void closeTcp(void);
static size_t circularBufferWrite(const char *data, size_t len);
static size_t circularBufferRead(char *dest, size_t max_len);

static ValkeyModuleCommandFilter *filter;
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
    {"incr", 1, 1, 1, 0},
    {"incrby", 1, 1, 1, 0},
    {"incrbyfloat", 1, 1, 1, 0},
    {"decr", 1, 1, 1, 0},
    {"decrby", 1, 1, 1, 0},
    {"setrange", 1, 1, 1, 0},
    {"getrange", 1, 1, 1, 0},
    /* Hash commands */
    {"hset", 1, 1, 1, 0},
    {"hsetnx", 1, 1, 1, 0},
    {"hget", 1, 1, 1, 0},
    {"hmset", 1, -1, 1, 0},
    {"hmget", 1, -1, 1, 0},
    {"hgetall", 1, 1, 1, 0},
    {"hdel", 1, 1, 1, 0},
    {"hlen", 1, 1, 1, 0},
    {"hexists", 1, 1, 1, 0},
    {"hkeys", 1, 1, 1, 0},
    {"hvals", 1, 1, 1, 0},
    {"hincrby", 1, 1, 1, 0},
    {"hincrbyfloat", 1, 1, 1, 0},
    {"hscan", 1, 1, 1, 0},
    {"hstrlen", 1, 1, 1, 0},
    /* List commands */
    {"lpush", 1, 1, 1, 0},
    {"rpush", 1, 1, 1, 0},
    {"lpop", 1, 1, 1, 0},
    {"rpop", 1, 1, 1, 0},
    {"llen", 1, 1, 1, 0},
    {"lindex", 1, 1, 1, 0},
    {"lrange", 1, 1, 1, 0},
    {"ltrim", 1, 1, 1, 0},
    {"lset", 1, 1, 1, 0},
    {"linsert", 1, 1, 1, 0},
    {"lrem", 1, 1, 1, 0},
    {"lpushx", 1, 1, 1, 0},
    {"rpushx", 1, 1, 1, 0},
    {"blpop", 1, -1, 1, 0},
    {"brpop", 1, -1, 1, 0},
    {"brpoplpush", 1, 2, 1, 0},
    {"rpoplpush", 1, 2, 1, 0},
    /* Set commands */
    {"sadd", 1, 1, 1, 0},
    {"srem", 1, 1, 1, 0},
    {"smembers", 1, 1, 1, 0},
    {"sismember", 1, 1, 1, 0},
    {"scard", 1, 1, 1, 0},
    {"spop", 1, 1, 1, 0},
    {"srandmember", 1, 1, 1, 0},
    {"smove", 1, 2, 1, 0},
    {"sscan", 1, 1, 1, 0},
    {"smismember", 1, 1, 1, 0},
    /* Sorted Set commands */
    {"zadd", 1, 1, 1, 0},
    {"zrem", 1, 1, 1, 0},
    {"zrange", 1, 1, 1, 0},
    {"zcard", 1, 1, 1, 0},
    {"zrevrange", 1, 1, 1, 0},
    {"zrangebyscore", 1, 1, 1, 0},
    {"zrevrangebyscore", 1, 1, 1, 0},
    {"zcount", 1, 1, 1, 0},
    {"zrank", 1, 1, 1, 0},
    {"zrevrank", 1, 1, 1, 0},
    {"zscore", 1, 1, 1, 0},
    {"zincrby", 1, 1, 1, 0},
    {"zremrangebyrank", 1, 1, 1, 0},
    {"zremrangebyscore", 1, 1, 1, 0},
    {"zremrangebylex", 1, 1, 1, 0},
    {"zrangebylex", 1, 1, 1, 0},
    {"zrevrangebylex", 1, 1, 1, 0},
    {"zlexcount", 1, 1, 1, 0},
    {"zscan", 1, 1, 1, 0},
    {"zpopmin", 1, 1, 1, 0},
    {"zpopmax", 1, 1, 1, 0},
    {"bzpopmin", 1, -1, 1, 0},
    {"bzpopmax", 1, -1, 1, 0},
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
    {"persist", 1, 1, 1, 0},
    {"dump", 1, 1, 1, 0},
    {"restore", 1, 1, 1, 0},
    {"touch", 1, -1, 1, 0},
    {"unlink", 1, -1, 1, 0},
    {"copy", 1, 2, 1, 0},
    {"move", 1, 1, 1, 0},
    {"object", 1, 1, 1, 0},
    {"expiretime", 1, 1, 1, 0},
    {"pexpiretime", 1, 1, 1, 0},
    /* Multi-key operations */
    {"sunion", 1, -1, 1, 0},
    {"sinter", 1, -1, 1, 0},
    {"sdiff", 1, -1, 1, 0},
    {"sunionstore", 1, -1, 1, 0},
    {"sinterstore", 1, -1, 1, 0},
    {"sdiffstore", 1, -1, 1, 0},
    /* Sorted set multi-key operations */
    {"zunionstore", 1, -1, 1, 0},
    {"zinterstore", 1, -1, 1, 0},
    /* Bit operations */
    {"setbit", 1, 1, 1, 0},
    {"getbit", 1, 1, 1, 0},
    {"bitcount", 1, 1, 1, 0},
    {"bitpos", 1, 1, 1, 0},
    {"bitfield", 1, 1, 1, 0},
    /* HyperLogLog commands */
    {"pfadd", 1, 1, 1, 0},
    {"pfcount", 1, -1, 1, 0},
    {"pfmerge", 1, -1, 1, 0},
    /* Geo commands */
    {"geoadd", 1, 1, 1, 0},
    {"geodist", 1, 1, 1, 0},
    {"geohash", 1, 1, 1, 0},
    {"geopos", 1, 1, 1, 0},
    {"georadius", 1, 1, 1, 0},
    {"georadiusbymember", 1, 1, 1, 0},
    {"geosearch", 1, 1, 1, 0},
    {"geosearchstore", 1, 2, 1, 0},
    /* Stream commands */
    {"xadd", 1, 1, 1, 0},
    {"xrange", 1, 1, 1, 0},
    {"xrevrange", 1, 1, 1, 0},
    {"xlen", 1, 1, 1, 0},
    {"xread", 1, -1, 1, 0},
    {"xreadgroup", 1, -1, 1, 0},
    {"xgroup", 1, 1, 1, 0},
    {"xack", 1, 1, 1, 0},
    {"xclaim", 1, 1, 1, 0},
    {"xautoclaim", 1, 1, 1, 0},
    {"xpending", 1, 1, 1, 0},
    {"xinfo", 1, 1, 1, 0},
    {"xdel", 1, 1, 1, 0},
    {"xtrim", 1, 1, 1, 0},
    /* End marker */
    {NULL, 0, 0, 0, 0}
};

// Get current monotonic timestamp in milliseconds
mstime_t getMonotonicMs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

// Get current timestamp in milliseconds using CLOCK_REALTIME to match ACL LOG
mstime_t getCurrentTimestampMs() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (mstime_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    } else {
        // Fallback to time() * 1000 if clock_gettime fails
        return (mstime_t)time(NULL) * 1000;
    }
}

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
            AuditModuleCommandInfo *info = ValkeyModule_Alloc(sizeof(AuditModuleCommandInfo));
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
                    snprintf(last_cmd_name, sizeof(last_cmd_name), "%s", cmd_name);
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
int initAuditLog(AuditConfig *config) {
    /* Initialize mutexes and condition variables */
    pthread_mutex_init(&config->log_mutex, NULL);
    pthread_mutex_init(&config->buffer_mutex, NULL);
    pthread_cond_init(&config->buffer_cond, NULL);
    
    /* Allocate buffer */
    config->buffer = ValkeyModule_Alloc(config->buffer_size);
    if (!config->buffer) {
        fprintf(stderr, "Failed to allocate audit log buffer\n");
        return -1;
    }
    
    /* Start worker thread */
    config->worker_running = 1;
    
    if (pthread_create(&config->worker_thread, NULL, auditLogWorker, config) != 0) {
        fprintf(stderr, "Failed to create audit log worker thread\n");
        ValkeyModule_Free(config->buffer);
        config->buffer = NULL;
        return -1;
    }
    
    return 0;
}

void shutdownAuditLog(void) {
    /* Signal worker thread to exit */
    pthread_mutex_lock(&config.buffer_mutex);
    config.shutdown_flag = 1;
    pthread_cond_signal(&config.buffer_cond);
    pthread_mutex_unlock(&config.buffer_mutex);
    
    /* Wait for worker thread to exit */
    pthread_join(config.worker_thread, NULL);
    
    /* Clean up resources */
    if (config.file_fd != -1) {
        close(config.file_fd);
        config.file_fd = -1;
    }
    
    if (config.protocol == PROTOCOL_SYSLOG) {
        closelog();
    }
    
    if (config.tcp_socket != -1) {
        closeTcp();
    }
    
    pthread_mutex_destroy(&config.log_mutex);
    pthread_mutex_destroy(&config.buffer_mutex);
    pthread_cond_destroy(&config.buffer_cond);
    
    if (config.buffer) {
        ValkeyModule_Free(config.buffer);
        config.buffer = NULL;
    }
    
    if (config.file_path) {
        ValkeyModule_Free(config.file_path);
        config.file_path = NULL;
    }
    
    if (config.tcp_host) {
        ValkeyModule_Free(config.tcp_host);
        config.tcp_host = NULL;
    }
}

// Worker thread function
static void *auditLogWorker(void *arg) {
    VALKEYMODULE_NOT_USED(arg);
    char temp_buffer[8192];  /* Temporary buffer for reading from circular buffer */
    
    #ifdef __linux__
        if (pthread_setname_np(pthread_self(), "audit_logging") != 0) {
        // Non-fatal, just log warning
        fprintf(stderr, "Warning: Could not set thread name\n");
    }
    #elif defined(__APPLE__)
        pthread_setname_np("audit_logging");
    #elif defined(__FreeBSD__)
        // FreeBSD version
        pthread_set_name_np(pthread_self(), "audit_logging");
    #endif

    while (1) {
        size_t bytes_read = 0;
        
        /* Wait for data or shutdown signal */
        pthread_mutex_lock(&config.buffer_mutex);
        while (config.buffer_used == 0 && !config.shutdown_flag) {
            /* Wait with a timeout of 1 second */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&config.buffer_cond, &config.buffer_mutex, &ts);
        }
        
        /* Check for shutdown */
        if (config.shutdown_flag && config.buffer_used == 0) {
            pthread_mutex_unlock(&config.buffer_mutex);
            break;
        }
        
        /* Read data from circular buffer */
        bytes_read = circularBufferRead(temp_buffer, sizeof(temp_buffer) - 1);
        pthread_mutex_unlock(&config.buffer_mutex);
        
        if (bytes_read > 0) {
            /* Ensure null-termination */
            temp_buffer[bytes_read] = '\0';
            
            /* Process based on protocol */
            switch (config.protocol) {
                case PROTOCOL_FILE:
                    /* Write to file */
                    if (config.file_fd != -1) {
                        ssize_t written = 0;
                        size_t remaining = bytes_read;
                        
                        while (remaining > 0) {
                            written = write(config.file_fd, temp_buffer + (bytes_read - remaining), remaining);
                            if (written <= 0) {
                                if (errno == EINTR) continue;
                                /* Handle write error */
                                fprintf(stderr, "Failed to write to audit log file: %s\n", strerror(errno));
                                break;
                            }
                            remaining -= written;
                        }
                    }
                    break;
                    
                case PROTOCOL_SYSLOG:
                    /* Send to syslog - split by lines */
                    {
                        char *line_start = temp_buffer;
                        char *line_end;
                        
                        while (line_start < temp_buffer + bytes_read) {
                            line_end = strchr(line_start, '\n');
                            if (!line_end) {
                                /* Last line without newline */
                                syslog(config.syslog_priority | config.syslog_facility, "%s", line_start);
                                break;
                            }
                            
                            *line_end = '\0';  /* Temporarily replace newline with null terminator */
                            syslog(config.syslog_priority | config.syslog_facility, "%s", line_start);
                            *line_end = '\n';  /* Restore newline */
                            
                            line_start = line_end + 1;
                        }
                    }
                    break;
                    
                case PROTOCOL_TCP:
                    /* Send to TCP endpoint */
                    if (!config.tcp_connected) {
                        /* Try to connect if not connected */
                        time_t now = time(NULL);
                        if (config.tcp_last_connect == 0 || 
                            now - config.tcp_last_connect > config.tcp_retry_interval_ms / 1000) {
                            if (connectTcp() == 0) {
                                config.tcp_connected = 1;
                                config.tcp_retry_count = 0;
                            } else {
                                config.tcp_retry_count++;
                                config.tcp_last_connect = now;
                            }
                        }
                    }
                    
                    if (config.tcp_connected) {
                        /* Send data if connected */
                        if (writeToTcp(temp_buffer, bytes_read) < 0) {
                            config.tcp_connected = 0;
                            closeTcp();
                        }
                    } else if (!config.tcp_buffer_on_disconnect) {
                        /* Discard data if not buffering during disconnect */
                        fprintf(stderr, "TCP disconnected and buffering disabled, discarding %zu bytes\n", bytes_read);
                    }
                    
                    break;
            }
        }
    }
    
    return NULL;
}

// Connect to TCP server
static int connectTcp(void) {
    struct addrinfo hints, *servinfo, *p;
    int sockfd = -1;
    int rv;
    char port_str[16];
    
    /* Check if we've exceeded retry limit */
    if (config.tcp_max_retries > 0 && config.tcp_retry_count >= config.tcp_max_retries) {
        if (!config.tcp_reconnect_on_failure) {
            fprintf(stderr, "TCP connection failed after %d attempts, giving up\n", config.tcp_retry_count);
            return -1;
        }
        /* Reset retry count if we're configured to keep trying */
        config.tcp_retry_count = 0;
    }
    
    snprintf(port_str, sizeof(port_str), "%d", config.tcp_port);
    
    /* Set up address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    
    /* Get address info */
    if ((rv = getaddrinfo(config.tcp_host, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(rv));
        return -1;
    }
    
    /* Loop through all results and connect to first available */
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        
        /* Set socket to non-blocking for timeout support */
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        
        /* Attempt connection */
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                close(sockfd);
                sockfd = -1;
                continue;
            }
            
            /* Wait for connection with timeout */
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLOUT;
            
            int poll_result = poll(&pfd, 1, config.tcp_timeout_ms);
            
            if (poll_result <= 0) {
                /* Timeout or error */
                close(sockfd);
                sockfd = -1;
                continue;
            }
            
            /* Check if connection succeeded */
            int error;
            socklen_t len = sizeof(error);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) {
                close(sockfd);
                sockfd = -1;
                continue;
            }
        }
        
        /* Set back to blocking mode */
        fcntl(sockfd, F_SETFL, flags);
        
        /* Connection successful */
        config.tcp_socket = sockfd;
        fprintf(stderr, "Connected to TCP audit server %s:%d\n", config.tcp_host, config.tcp_port);
        freeaddrinfo(servinfo);
        return 0;
    }
    
    /* Failed to connect to any address */
    fprintf(stderr, "Failed to connect to TCP audit server %s:%d\n", config.tcp_host, config.tcp_port);
    freeaddrinfo(servinfo);
    return -1;
}

// Write data to TCP connection
static int writeToTcp(const char *data, size_t len) {
    if (config.tcp_socket == -1) {
        return -1;
    }
    
    size_t total_sent = 0;
    ssize_t sent;
    
    /* Set write timeout */
    struct timeval timeout;
    timeout.tv_sec = config.tcp_timeout_ms / 1000;
    timeout.tv_usec = (config.tcp_timeout_ms % 1000) * 1000;
    setsockopt(config.tcp_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    /* Send data */
    while (total_sent < len) {
        sent = send(config.tcp_socket, data + total_sent, len - total_sent, 0);
        
        if (sent <= 0) {
            if (errno == EINTR) {
                continue;  /* Retry on interrupt */
            }
            
            fprintf(stderr, "TCP send error: %s\n", strerror(errno));
            return -1;
        }
        
        total_sent += sent;
    }
    
    return 0;
}

// Close TCP connection
static void closeTcp(void) {
    if (config.tcp_socket != -1) {
        close(config.tcp_socket);
        config.tcp_socket = -1;
    }
    config.tcp_connected = 0;
}

// Write data to circular buffer
static size_t circularBufferWrite(const char *data, size_t len) {
    if (!config.buffer || len == 0) {
        return 0;
    }
    
    /* Check if buffer is full */
    if (config.buffer_used == config.buffer_size) {
        return 0;
    }
    
    /* Calculate available space */
    size_t available = config.buffer_size - config.buffer_used;
    size_t to_write = (len > available) ? available : len;
    
    /* Handle wrap-around if needed */
    if (config.buffer_head + to_write <= config.buffer_size) {
        /* Simple case: no wrap-around */
        memcpy(config.buffer + config.buffer_head, data, to_write);
        config.buffer_head = (config.buffer_head + to_write) % config.buffer_size;
    } else {
        /* Wrap-around case */
        size_t first_chunk = config.buffer_size - config.buffer_head;
        size_t second_chunk = to_write - first_chunk;
        
        /* Write first chunk to end of buffer */
        memcpy(config.buffer + config.buffer_head, data, first_chunk);
        
        /* Write second chunk to beginning of buffer */
        memcpy(config.buffer, data + first_chunk, second_chunk);
        
        config.buffer_head = second_chunk;
    }
    
    config.buffer_used += to_write;
    return to_write;
}

// Read data from circular buffer
static size_t circularBufferRead(char *dest, size_t max_len) {
    if (!config.buffer || config.buffer_used == 0 || max_len == 0) {
        return 0;
    }
    
    /* Calculate amount to read */
    size_t to_read = (max_len > config.buffer_used) ? config.buffer_used : max_len;
    
    /* Handle wrap-around if needed */
    if (config.buffer_tail + to_read <= config.buffer_size) {
        /* Simple case: no wrap-around */
        memcpy(dest, config.buffer + config.buffer_tail, to_read);
        config.buffer_tail = (config.buffer_tail + to_read) % config.buffer_size;
    } else {
        /* Wrap-around case */
        size_t first_chunk = config.buffer_size - config.buffer_tail;
        size_t second_chunk = to_read - first_chunk;
        
        /* Read first chunk from end of buffer */
        memcpy(dest, config.buffer + config.buffer_tail, first_chunk);
        
        /* Read second chunk from beginning of buffer */
        memcpy(dest + first_chunk, config.buffer, second_chunk);
        
        config.buffer_tail = second_chunk;
    }
    
    config.buffer_used -= to_read;
    return to_read;
}

void writeAuditLog(const char *format, ...) {
    if (!config.enabled || !format) {
        return;
    }
    
    /* Format message */
    va_list args;
    char message[4096];
    
    /* Format message */
    va_start(args, format);
    vsnprintf(message, sizeof(message) - 2, format, args);
    va_end(args);
    
    /* Add newline if needed */
    size_t len = strlen(message);
    if (message[len-1] != '\n') {
        message[len] = '\n';
        message[len+1] = '\0';
        len++;
    }
    
    /* Handle immediate output for unbuffered protocols */
    pthread_mutex_lock(&config.log_mutex);
    
    if (config.buffer_size == 0) {
        /* Unbuffered output */
        switch (config.protocol) {
            case PROTOCOL_FILE:
                if (config.file_fd != -1) {
                    write(config.file_fd, message, len);
                }
                break;
                
            case PROTOCOL_SYSLOG:
                /* Remove newline for syslog */
                if (message[len-1] == '\n') {
                    message[len-1] = '\0';
                }
                syslog(config.syslog_priority | config.syslog_facility, "%s", message);
                break;
                
            case PROTOCOL_TCP:
                if (config.tcp_connected) {
                    writeToTcp(message, len);
                }
                break;
        }
    } else {
        /* Buffered output */
        pthread_mutex_lock(&config.buffer_mutex);
        size_t written = circularBufferWrite(message, len);
        
        /* Signal worker thread that new data is available */
        if (written > 0) {
            pthread_cond_signal(&config.buffer_cond);
        }
        
        pthread_mutex_unlock(&config.buffer_mutex);
        
        /* If we couldn't write all data, log an error */
        if (written < len) {
            fprintf(stderr, "Audit log buffer full, discarded %zu bytes\n", len - written);
        }
    }
    
    pthread_mutex_unlock(&config.log_mutex);
}

static void formatEventText(char *buffer, size_t size, const char *category, const char *command, const char *details, const char *username, const char *client_ip, int client_port, const char *flag) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(buffer, size, "[%s] [%s] %s %s %s %s:%d %s %s", 
             timestamp, category, command, flag, username, client_ip, client_port, server_hostname, details ? details : "");
}

static void formatEventJson(char *buffer, size_t size, const char *category, const char *command, const char *details, const char *username, const char *client_ip, int client_port, const char * flag) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(buffer, size,
        "{\"timestamp\":\"%s\",\"category\":\"%s\",\"command\":\"%s\",\"result\":\"%s\",\"username\":\"%s\",\"client_ip\":\"%s\",\"client_port\":%d,\"server_hostname\":\"%s\",\"details\":\"%s\"}",
        timestamp, category, command, flag, username, client_ip, client_port, server_hostname, details ? details : "null");
}

static void formatEventCsv(char *buffer, size_t size, const char *category, const char *command, const char *details, const char *username, const char *client_ip, int client_port, const char * flag) {
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
    
    snprintf(buffer, size, "%s,%s,%s,%s,%s,%s,%d,%s,%s", 
             timestamp, category, command, flag, username, client_ip, client_port, server_hostname, escaped_details);
}

static void logAuditEvent(const char *category, const char *command, const char *details, const char *username, const char *client_ip, int client_port, int flag) {
    char buffer[4096];
    const char* flag_texts[] = {"FAILURE", "SUCCESS", "ATTEMPT", "EXECUTE", "ERROR", "DEBUG"};
    const char* flag_text = flag_texts[flag];

    switch(config.format) {
        case FORMAT_JSON:
            formatEventJson(buffer, sizeof(buffer), category, command, details, username, client_ip, client_port, flag_text);
            break;
        case FORMAT_CSV:
            formatEventCsv(buffer, sizeof(buffer), category, command, details, username, client_ip, client_port, flag_text);
            break;
        case FORMAT_TEXT:
        default:
            formatEventText(buffer, sizeof(buffer), category, command, details, username, client_ip, client_port, flag_text);
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
        if (current->username)  ValkeyModule_Free(current->username);
        if (current->ip_address) ValkeyModule_Free(current->ip_address);
        ValkeyModule_Free(current);
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
    
    ExclusionRule *new_rule = (ExclusionRule*)ValkeyModule_Alloc(sizeof(ExclusionRule));
    if (new_rule == NULL) return;  // Out of memory
    
    // Initialize fields
    new_rule->username = username ? ValkeyModule_Strdup(username) : NULL;
    new_rule->ip_address = ip_address ? ValkeyModule_Strdup(ip_address) : NULL;
    
    // Check for memory allocation failures
    if ((username && new_rule->username == NULL) || 
        (ip_address && new_rule->ip_address == NULL)) {
        if (new_rule->username)  ValkeyModule_Free(new_rule->username);
        if (new_rule->ip_address)  ValkeyModule_Free(new_rule->ip_address);
        ValkeyModule_Free(new_rule);
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

    if (loglevel_debug) {
        printf("%s\n", log_message);
    }
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
    char *list_copy = ValkeyModule_Strdup(csv_list);
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
                        if (loglevel_debug) {
                            printf("%s\n", log_message);
                        }
        
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

    ValkeyModule_Free(list_copy);
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
    
    return VALKEYMODULE_OK;
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
void storeClientInfo(uint64_t client_id, const char *username, const char *ip_address, 
                     int client_port, int no_audit, mstime_t auth_timestamp) {
    // Allocate memory for the new entry
    ClientUsernameEntry *entry = ValkeyModule_Alloc(sizeof(ClientUsernameEntry));
    if (entry == NULL) {
        return;
    }
    
    // Make a copy of the username
    char *username_copy = ValkeyModule_Strdup(username);
    if (username_copy == NULL) {
        // Handle strdup failure
        ValkeyModule_Free(entry);
        return;
    }
    
    // Make a copy of the IP address
    char *ip_copy = NULL;
    if (ip_address != NULL) {
        ip_copy = ValkeyModule_Strdup(ip_address);
        if (ip_copy == NULL) {
            // Handle strdup failure for IP
            ValkeyModule_Free(username_copy);
            ValkeyModule_Free(entry);
            return;
        }
    }
    
    // Initialize the entry
    entry->client_id = client_id;
    entry->username = username_copy;
    entry->ip_address = ip_copy;
    entry->client_port = client_port;
    entry->no_audit = no_audit;
    entry->auth_timestamp = auth_timestamp;
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
                ValkeyModule_Free(current->username);  // Free the old username
                current->username = username_copy;
                
                // Update IP address
                if (current->ip_address != NULL) {
                    ValkeyModule_Free(current->ip_address);
                }
                current->ip_address = ip_copy;
                
                current->client_port = client_port;
                current->no_audit = no_audit;
                current->auth_timestamp = auth_timestamp;  
                ValkeyModule_Free(entry);  
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
            ValkeyModule_Free(entry->username);
            if (entry->ip_address != NULL) {
                ValkeyModule_Free(entry->ip_address);
            }
            ValkeyModule_Free(entry);
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
            ValkeyModule_Free(current->username);
            if (current->ip_address != NULL) {
                ValkeyModule_Free(current->ip_address);
            }
            ValkeyModule_Free(current);
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
                      "Client ID: %llu, Username: %s, ClientIP: %s, ClientPort: %d, Auth Timestamp: %lld, NoAudit: %d \n", 
                      (unsigned long long)entry->client_id, 
                      entry->username ? entry->username : "NULL",
                      entry->ip_address,
                      entry->client_port,
                      (long long)entry->auth_timestamp,
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
        snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), "  (empty)\n");
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

// Helper function to update client username when auth fails with different username
void updateClientUsernameOnAuthFailure(ValkeyModuleCtx *ctx, uint64_t client_id) {
    ClientUsernameEntry *client = getClientEntry(client_id);
    if (client) {
        // Free the old username if it exists
        if (client->username) {
            ValkeyModule_Free(client->username);
            client->username = NULL;
        }
        
        // Get the correct username from the clientId
        ValkeyModuleString *correct_username_str = ValkeyModule_GetClientUserNameById(ctx, client_id);
        if (correct_username_str) {
            size_t username_len;
            const char *correct_username = ValkeyModule_StringPtrLen(correct_username_str, &username_len);
            
            if (correct_username && username_len > 0) {
                // Allocate memory for the new username
                client->username = ValkeyModule_Alloc(username_len + 1);
                if (client->username) {
                    strncpy(client->username, correct_username, username_len);
                    client->username[username_len] = '\0';  // Ensure null termination
                }
            }
            
            // Free the ValkeyModuleString
            ValkeyModule_FreeString(ctx, correct_username_str);
        }
    }
}

// Timer callback to check auth result
// NOTE: ACL LOG only contains FAILURES, so:
// - If we find a matching entry = AUTH FAILED
// - If we find NO matching entry = AUTH SUCCEEDED
void checkAuthResultTimer(ValkeyModuleCtx *ctx, void *data) {
    ValkeyModule_AutoMemory(ctx);  
    
    uint64_t *client_id_ptr = (uint64_t *)data;
    if (!client_id_ptr) return;
    
    uint64_t client_id = *client_id_ptr;
    
    // Find the client info in our hash table
    ClientUsernameEntry *client_entry = getClientEntry(client_id);
    if (!client_entry) {
        ValkeyModule_Free(client_id_ptr);  
        return;
    }
    
    // Skip processing if this entry has no auth timestamp
    if (client_entry->auth_timestamp == 0) {
        ValkeyModule_Free(client_id_ptr);
        return;
    }
    
    ValkeyModuleCallReply *reply = NULL;
    int auth_failed = 0;
    char actual_username[256] = {0};
    char failure_reason[512] = {0};
    
    char debug_msg[512];
    if (loglevel_debug) {
        snprintf(debug_msg, sizeof(debug_msg), 
                "Timer checking auth result for client #%llu, auth_timestamp: %lld", 
                (unsigned long long)client_id, (long long)client_entry->auth_timestamp);
        logAuditEvent("DEBUG", "TIMER", debug_msg, 
                    client_entry->username ? client_entry->username : "unknown", 
                    client_entry->ip_address ? client_entry->ip_address : "unknown",
                    client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
    }
    // Get ALL recent ACL LOG entries (no limit - we'll stop based on timestamp)
    reply = ValkeyModule_Call(ctx, "ACL", "0c", "LOG");
    if (!reply) {
        goto cleanup;
    }
    
    if (ValkeyModule_CallReplyType(reply) == VALKEYMODULE_REPLY_ERROR) {
        goto cleanup;
    }
    
    if (ValkeyModule_CallReplyType(reply) != VALKEYMODULE_REPLY_ARRAY) {
        goto cleanup;
    }
    
    size_t num_entries = ValkeyModule_CallReplyLength(reply);
    
    if (loglevel_debug) {
        snprintf(debug_msg, sizeof(debug_msg), "Found %zu ACL LOG entries to check, reply type: %d", 
                num_entries, ValkeyModule_CallReplyType(reply));
        logAuditEvent("DEBUG", "TIMER", debug_msg, 
                    client_entry->username ? client_entry->username : "unknown", 
                    client_entry->ip_address ? client_entry->ip_address : "unknown",
                    client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
    }

    // Look for a matching auth failure in the ACL entries
    // since ACL LOG aggregates, check the last-update-timestamp
    for (size_t i = 0; i < num_entries; i++) {
        ValkeyModuleCallReply *entry = ValkeyModule_CallReplyArrayElement(reply, i);
        size_t entry_len = ValkeyModule_CallReplyLength(entry);

        if (loglevel_debug) {
            if (ValkeyModule_CallReplyType(entry) != VALKEYMODULE_REPLY_ARRAY) {
                snprintf(debug_msg, sizeof(debug_msg), "Entry %zu is not an array, type: %d", 
                        i, ValkeyModule_CallReplyType(entry));
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                            client_entry->username ? client_entry->username : "unknown", 
                            client_entry->ip_address ? client_entry->ip_address : "unknown",
                            client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                continue;
            }
            if (entry_len < 10) {
                snprintf(debug_msg, sizeof(debug_msg), "Entry %zu too short: %zu fields", i, entry_len);
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                            client_entry->username ? client_entry->username : "unknown", 
                            client_entry->ip_address ? client_entry->ip_address : "unknown",
                            client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                continue;
            }
        }

        // Parse the ACL LOG entry
        char reason[64] = {0};
        char username[256] = {0}; 
        char client_info_log[1024] = {0};
        char context[64] = {0};
        mstime_t timestamp = 0;
        long long count = 1;
        int found_client_match = 0;
        
        // Single pass: extract all fields in one go
        for (size_t j = 0; j < entry_len; j += 2) {
            if (j + 1 >= entry_len) break;
            
            ValkeyModuleCallReply *key_reply = ValkeyModule_CallReplyArrayElement(entry, j);
            ValkeyModuleCallReply *value_reply = ValkeyModule_CallReplyArrayElement(entry, j + 1);
            size_t key_len;
            const char *key_ptr = ValkeyModule_CallReplyStringPtr(key_reply, &key_len);
            
            if (loglevel_debug) {
                if (!key_reply || !value_reply) {
                    snprintf(debug_msg, sizeof(debug_msg), "NULL reply at index %zu", j);
                    logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                client_entry->username ? client_entry->username : "unknown", 
                                client_entry->ip_address ? client_entry->ip_address : "unknown",
                                client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                    continue;
                }
                
                if (!key_ptr) {
                    snprintf(debug_msg, sizeof(debug_msg), "Key at index %zu is not a string, type: %d", 
                            j, ValkeyModule_CallReplyType(key_reply));
                    logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                client_entry->username ? client_entry->username : "unknown", 
                                client_entry->ip_address ? client_entry->ip_address : "unknown",
                                client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                    continue;
                }
            }

            // Create a null-terminated copy of the key for proper string comparison
            char key[64] = {0};
            if (key_len > 0 && key_len < sizeof(key) - 1) {
                strncpy(key, key_ptr, key_len);
                key[key_len] = '\0';
            } else {
                continue; 
            }
            
            if (loglevel_debug) {
                snprintf(debug_msg, sizeof(debug_msg), "Key[%zu]: '%s' (len=%zu, type=%d)", 
                        j, key, key_len, ValkeyModule_CallReplyType(key_reply));
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                            client_entry->username ? client_entry->username : "unknown", 
                            client_entry->ip_address ? client_entry->ip_address : "unknown",
                            client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                
                int value_type = ValkeyModule_CallReplyType(value_reply);
                if (value_type == VALKEYMODULE_REPLY_STRING) {
                    size_t value_len;
                    const char *value = ValkeyModule_CallReplyStringPtr(value_reply, &value_len);
                    snprintf(debug_msg, sizeof(debug_msg), "Value[%zu]: '%.*s' (len=%zu, type=STRING)", 
                            j+1, (int)(value_len > 50 ? 50 : value_len), value ? value : "NULL", value_len);
                } else if (value_type == VALKEYMODULE_REPLY_INTEGER) {
                    long long value = ValkeyModule_CallReplyInteger(value_reply);
                    snprintf(debug_msg, sizeof(debug_msg), "Value[%zu]: %lld (type=INTEGER)", j+1, value);
                } else {
                    snprintf(debug_msg, sizeof(debug_msg), "Value[%zu]: (type=%d - not string or int)", j+1, value_type);
                }
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                            client_entry->username ? client_entry->username : "unknown", 
                            client_entry->ip_address ? client_entry->ip_address : "unknown",
                            client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
            }

            // COPY strings to local buffers instead of storing pointers
            if (strcmp(key, "reason") == 0) {
                if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_STRING) {
                    size_t reason_len;
                    const char *reason_ptr = ValkeyModule_CallReplyStringPtr(value_reply, &reason_len);
                    if (reason_ptr && reason_len > 0 && reason_len < sizeof(reason) - 1) {
                        strncpy(reason, reason_ptr, reason_len);
                        reason[reason_len] = '\0';  // Ensure null termination
                        if (loglevel_debug) {
                            snprintf(debug_msg, sizeof(debug_msg), "COPIED reason: '%.20s'", reason);
                            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                     client_entry->username ? client_entry->username : "unknown", 
                                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                                     client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                        }
                    }
                }
            } else if (strcmp(key, "username") == 0) {
                if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_STRING) {
                    size_t username_len;
                    const char *username_ptr = ValkeyModule_CallReplyStringPtr(value_reply, &username_len);
                    if (username_ptr && username_len > 0 && username_len < sizeof(username) - 1) {
                        strncpy(username, username_ptr, username_len);
                        username[username_len] = '\0';  // Ensure null termination
                        if (loglevel_debug) {
                            snprintf(debug_msg, sizeof(debug_msg), "COPIED username: '%.50s'", username);
                            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                     client_entry->username ? client_entry->username : "unknown", 
                                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                                     client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                            }
                    }
                }
            } else if (strcmp(key, "client-info") == 0) {
                if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_STRING) {
                    size_t client_info_len;
                    const char *client_info_ptr = ValkeyModule_CallReplyStringPtr(value_reply, &client_info_len);
                    if (client_info_ptr && client_info_len > 0 && client_info_len < sizeof(client_info_log) - 1) {
                        strncpy(client_info_log, client_info_ptr, client_info_len);
                        client_info_log[client_info_len] = '\0';  // Ensure null termination
                    }
                }
            } else if (strcmp(key, "context") == 0) {
                if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_STRING) {
                    size_t context_len;
                    const char *context_ptr = ValkeyModule_CallReplyStringPtr(value_reply, &context_len);
                    if (context_ptr && context_len > 0 && context_len < sizeof(context) - 1) {
                        strncpy(context, context_ptr, context_len);
                        context[context_len] = '\0';  // Ensure null termination
                        if (loglevel_debug) {
                            snprintf(debug_msg, sizeof(debug_msg), "COPIED context: '%.20s'", context);
                            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                     client_entry->username ? client_entry->username : "unknown", 
                                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                                     client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                        }
                    }
                }
            } else if (strcmp(key, "count") == 0) {
                if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_INTEGER) {
                    count = ValkeyModule_CallReplyInteger(value_reply);
                }
            } else if (strcmp(key, "timestamp-last-updated") == 0) {
                if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_INTEGER) {
                    timestamp = (mstime_t)ValkeyModule_CallReplyInteger(value_reply);
                    if (loglevel_debug) {
                        snprintf(debug_msg, sizeof(debug_msg), "ASSIGNED timestamp: %lld", (long long)timestamp);
                        logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                 client_entry->username ? client_entry->username : "unknown", 
                                 client_entry->ip_address ? client_entry->ip_address : "unknown",
                                 client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                    }
                }
            }
        }
        
        // Check if this entry is older than our auth attempt, skip if so
        // (ACL LOG is ordered newest first, so all subsequent entries will be even older)
        if (timestamp > 0 && timestamp < client_entry->auth_timestamp) {
            if (loglevel_debug) {
                snprintf(debug_msg, sizeof(debug_msg), 
                    "Entry %zu timestamp %lld is older than auth_timestamp %lld - stopping scan", 
                    i, (long long)timestamp, (long long)client_entry->auth_timestamp);
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                         client_entry->username ? client_entry->username : "unknown", 
                         client_entry->ip_address ? client_entry->ip_address : "unknown",
                         client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                }
            break; // Stop here - no point checking older entries
        }
        
        if (loglevel_debug) {
            snprintf(debug_msg, sizeof(debug_msg), 
                "After parsing: reason='%s', context='%s', username='%s', timestamp=%lld", 
                reason[0] ? reason : "null", 
                context[0] ? context : "null", 
                username[0] ? username : "null", 
                (long long)timestamp);
            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                     client_entry->username ? client_entry->username : "unknown", 
                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                     client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
        
            snprintf(debug_msg, sizeof(debug_msg), 
                "Checking condition: reason=%s, strcmp=%d, timestamp=%lld > 0", 
                reason[0] ? reason : "NULL", 
                reason[0] ? strcmp(reason, "auth") : -999,
                (long long)timestamp);
            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                     client_entry->username ? client_entry->username : "unknown", 
                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                     client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
        }

        // Check if this ACL LOG entry matches our auth attempt
        if (reason[0] && strcmp(reason, "auth") == 0 && timestamp > 0) {
            if (loglevel_debug) {
                snprintf(debug_msg, sizeof(debug_msg), 
                    "Found auth entry %zu: reason=%s, context=%s, username=%s, timestamp=%lld", 
                    i, reason, context[0] ? context : "null", username[0] ? username : "null", (long long)timestamp);
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                         client_entry->username ? client_entry->username : "unknown", 
                         client_entry->ip_address ? client_entry->ip_address : "unknown",
                         client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
            }

            // Ensure this is a toplevel auth failure (not from script/multi/module)
            if (context[0] && strcmp(context, "toplevel") != 0) {
                if (loglevel_debug) {
                    snprintf(debug_msg, sizeof(debug_msg), "Skipping non-toplevel auth failure: %s", context);
                    logAuditEvent("DEBUG", "TIMER", debug_msg, 
                             client_entry->username ? client_entry->username : "unknown", 
                             client_entry->ip_address ? client_entry->ip_address : "unknown",
                             client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                }
                continue; // Skip non-toplevel auth failures
            }
            
            // Check if the timestamp is close to our auth attempt (within 1 second for faster response)
            mstime_t time_diff = (timestamp > client_entry->auth_timestamp) ? 
                                (timestamp - client_entry->auth_timestamp) : 
                                (client_entry->auth_timestamp - timestamp);
            
            if (loglevel_debug) {
                snprintf(debug_msg, sizeof(debug_msg), 
                    "Time difference: %lld ms (limit: 1000ms)", (long long)time_diff);
                logAuditEvent("DEBUG", "TIMER", debug_msg, 
                         client_entry->username ? client_entry->username : "unknown", 
                         client_entry->ip_address ? client_entry->ip_address : "unknown",
                         client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
            }             

            if (time_diff < 1000) {  // Within 1 second
                // Check if client info contains our client ID or IP
                if (client_info_log[0]) {
                    char client_id_str[32];
                    snprintf(client_id_str, sizeof(client_id_str), "id=%llu", 
                            (unsigned long long)client_id);
                    
                    if (loglevel_debug) {
                        snprintf(debug_msg, sizeof(debug_msg), 
                            "Checking client match: looking for '%s' or '%s' in '%.200s'", 
                            client_id_str, 
                            client_entry->ip_address ? client_entry->ip_address : "null",
                            client_info_log);
                        logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                 client_entry->username ? client_entry->username : "unknown", 
                                 client_entry->ip_address ? client_entry->ip_address : "unknown",
                                 client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                    }

                    if (strstr(client_info_log, client_id_str) || 
                        (client_entry->ip_address && strstr(client_info_log, client_entry->ip_address))) {
                        found_client_match = 1;
                        
                        if (loglevel_debug) {
                            snprintf(debug_msg, sizeof(debug_msg), "CLIENT MATCH FOUND!");
                            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                     client_entry->username ? client_entry->username : "unknown", 
                                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                                     client_entry->client_port, EVENT_DEBUG);
                            }
                    } else {
                        if (loglevel_debug) {
                            snprintf(debug_msg, sizeof(debug_msg), "No client match found");
                            logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                     client_entry->username ? client_entry->username : "unknown", 
                                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                                     client_entry->client_port, EVENT_DEBUG);
                        }
                    }
                }
                
                if (found_client_match) {
                    auth_failed = 1;
                    snprintf(failure_reason, sizeof(failure_reason), 
                            "-WRONGPASS invalid username-password pair or user is disabled. Context: %s, Client: %s, Username: %s, Count: %lld",
                            context[0] ? context : "unknown", 
                            client_entry->username ? client_entry->username : "unknown", 
                            username[0] ? username : "unknown", 
                            count);
                    
                    if (loglevel_debug) {
                        snprintf(debug_msg, sizeof(debug_msg), "AUTH FAILURE DETECTED - breaking loop");
                        logAuditEvent("DEBUG", "TIMER", debug_msg, 
                                 client_entry->username ? client_entry->username : "unknown", 
                                 client_entry->ip_address ? client_entry->ip_address : "unknown",
                                 client_entry->client_port ? client_entry->client_port : 0, EVENT_DEBUG);
                        }
                    break;
                }
            }
        }
    }
    
    // Log the result
    if (auth_failed) {
        // Authentication failed
        char audit_message[1024];
        snprintf(audit_message, sizeof(audit_message),
                "Authentication FAILED for client #%llu (%s:%d) - %s",
                (unsigned long long)client_id, 
                client_entry->ip_address ? client_entry->ip_address : "unknown",
                client_entry->client_port,
                "-WRONGPASS invalid username-password pair or user is disabled.");
        
        logAuditEvent("AUTH", "AUTH", audit_message, 
                     actual_username[0] ? actual_username : 
                     (client_entry->username ? client_entry->username : "unknown"), 
                     (client_entry->ip_address ? client_entry->ip_address : "unknown"),
                     client_entry->client_port ? client_entry->client_port : 0, EVENT_FAILURE);
        
        // Update client hash table with correct username
        updateClientUsernameOnAuthFailure(ctx, client_id);
    } else {
        // No matching failure found in ACL LOG = AUTH SUCCEEDED
        // (ACL LOG only contains failures, absence means success)
        char audit_message[1024];
        snprintf(audit_message, sizeof(audit_message),
                "Authentication SUCCESS for username: %s from client #%llu (%s:%d)",
                client_entry->username ? client_entry->username : "unknown",
                (unsigned long long)client_id,
                client_entry->ip_address ? client_entry->ip_address : "unknown",
                client_entry->client_port);
        
        logAuditEvent("AUTH", "AUTH", audit_message, 
                     client_entry->username ? client_entry->username : "unknown", 
                     client_entry->ip_address ? client_entry->ip_address : "unknown",
                     client_entry->client_port ? client_entry->client_port : 0, EVENT_SUCCESS);
    }
    
cleanup:
    if (reply) {
        ValkeyModule_FreeCallReply(reply);
    }
    
    // Free the client ID pointer using ValkeyModule_Free
    ValkeyModule_Free(client_id_ptr);
}

// Create a timer to check auth result after a short delay
int scheduleAuthResultCheck(ValkeyModuleCtx *ctx, uint64_t client_id) {
    
    // Allocate memory for client ID to pass to timer
    uint64_t *client_id_ptr = ValkeyModule_Alloc(sizeof(uint64_t));
    if (!client_id_ptr) {
        return VALKEYMODULE_ERR;
    }
    
    *client_id_ptr = client_id;
    
    // Create the timer
    ValkeyModuleTimerID timer_id = ValkeyModule_CreateTimer(ctx, 
                                                           AUTH_RESULT_CHECK_DELAY_MS,
                                                           checkAuthResultTimer, 
                                                           client_id_ptr);
    
    if (timer_id == 0) {
        ValkeyModule_Free(client_id_ptr);
        return VALKEYMODULE_ERR;
    }
    
    return VALKEYMODULE_OK;
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
        case PROTOCOL_TCP:
            protocol_str = "tcp";
            // Format TCP connection as "host:port"
            if (config.tcp_host && config.tcp_port > 0) {
                // Need to allocate space for host:port format
                size_t tcp_param_len = strlen(config.tcp_host) + 16; // 16 chars should be enough for port number + colon + null
                char *tcp_param = ValkeyModule_Alloc(tcp_param_len);
                if (tcp_param) {
                    snprintf(tcp_param, tcp_param_len, "%s:%d", config.tcp_host, config.tcp_port);
                    param_str = tcp_param;
                } else {
                    param_str = "";
                }
            } else {
                param_str = "";
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
    
    // Trim whitespace from input
    while (len > 0 && (*input == ' ' || *input == '\t' || *input == '\n' || *input == '\r')) {
        input++;
        len--;
    }
    while (len > 0 && (input[len-1] == ' ' || input[len-1] == '\t' || input[len-1] == '\n' || input[len-1] == '\r')) {
        len--;
    }
    
    // Process based on protocol type
    if (len >= 5 && strncasecmp(input, "file ", 5) == 0) {
        ValkeyModule_Log(NULL, "notice", "Audit: Matched file protocol");
        const char *filepath = input + 5;
        
        // Close existing connections
        if (config.protocol == PROTOCOL_FILE && config.file_fd != -1) {
            close(config.file_fd);
            config.file_fd = -1;
        } else if (config.protocol == PROTOCOL_SYSLOG) {
            closelog();
        } else if (config.protocol == PROTOCOL_TCP && config.tcp_socket != -1) {
            close(config.tcp_socket);
            config.tcp_socket = -1;
        }
        
        // Free existing file_path if any
        if (config.file_path) {
            ValkeyModule_Free(config.file_path); 
            config.file_path = NULL;
        }
        
        // Free existing TCP host if any
        if (config.tcp_host) {
            ValkeyModule_Free(config.tcp_host);
            config.tcp_host = NULL;
        }
        
        // Create a new copy of the filepath
        config.file_path = ValkeyModule_Strdup(filepath); 
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
    else if (len >= 7 && strncasecmp(input, "syslog ", 7) == 0) {
        ValkeyModule_Log(NULL, "notice", "Audit: Matched syslog protocol");
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
        } else if (config.protocol == PROTOCOL_TCP && config.tcp_socket != -1) {
            close(config.tcp_socket);
            config.tcp_socket = -1;
        }
        
        // Free existing file_path if any
        if (config.file_path) {
            ValkeyModule_Free(config.file_path);
            config.file_path = NULL;
        }
        
        // Free existing TCP host if any
        if (config.tcp_host) {
            ValkeyModule_Free(config.tcp_host);
            config.tcp_host = NULL;
        }
        
        // Update config
        config.protocol = PROTOCOL_SYSLOG;
        config.syslog_facility = facility;
        
        // Initialize syslog
        openlog("valkey-audit", LOG_PID, config.syslog_facility);
        
        return VALKEYMODULE_OK;
    }
    else if (len >= 4 && strncasecmp(input, "tcp ", 4) == 0) {
        ValkeyModule_Log(NULL, "notice", "Audit: Matched TCP protocol");
        const char *host_port = input + 4;
        size_t host_port_len = len - 4;
        
        // Find colon in the remaining string
        const char *colon_pos = NULL;
        for (size_t i = 0; i < host_port_len; i++) {
            if (host_port[i] == ':') {
                colon_pos = host_port + i;
                break;
            }
        }
        
        if (!colon_pos) {
            *err = ValkeyModule_CreateString(NULL, "ERR TCP format must be 'tcp host:port'", 38);
            return VALKEYMODULE_ERR;
        }
        
        // Extract host
        size_t host_len = colon_pos - host_port;
        if (host_len == 0) {
            *err = ValkeyModule_CreateString(NULL, "ERR TCP host cannot be empty", 28);
            return VALKEYMODULE_ERR;
        }
        
        char *host = ValkeyModule_Alloc(host_len + 1);
        if (!host) {
            *err = ValkeyModule_CreateString(NULL, "ERR Memory allocation failed", 27);
            return VALKEYMODULE_ERR;
        }
        strncpy(host, host_port, host_len);
        host[host_len] = '\0';
        
        // Extract port
        const char *port_str = colon_pos + 1;
        int port = atoi(port_str);
        if (port <= 0 || port > 65535) {
            ValkeyModule_Free(host);
            *err = ValkeyModule_CreateString(NULL, "ERR Invalid port number", 23);
            return VALKEYMODULE_ERR;
        }
        
        ValkeyModule_Log(NULL, "notice", "Audit: TCP parsed: host='%s', port=%d", host, port);
        
        // Close existing connections
        if (config.protocol == PROTOCOL_FILE && config.file_fd != -1) {
            close(config.file_fd);
            config.file_fd = -1;
        } else if (config.protocol == PROTOCOL_SYSLOG) {
            closelog();
        } else if (config.protocol == PROTOCOL_TCP && config.tcp_socket != -1) {
            close(config.tcp_socket);
            config.tcp_socket = -1;
        }
        
        // Free existing paths/hosts
        if (config.file_path) {
            ValkeyModule_Free(config.file_path);
            config.file_path = NULL;
        }
        if (config.tcp_host) {
            ValkeyModule_Free(config.tcp_host);
            config.tcp_host = NULL;
        }
        
        // Update config
        config.protocol = PROTOCOL_TCP;
        config.tcp_host = host;
        config.tcp_port = port;
        config.tcp_socket = -1; // Will be connected on first use
        
        ValkeyModule_Log(NULL, "notice", "Audit: TCP protocol configured successfully");
        return VALKEYMODULE_OK;
    }  
    else {
        ValkeyModule_Log(NULL, "notice", "Audit: No protocol matched, input was: '%.*s'", (int)len, input);
        *err = ValkeyModule_CreateString(NULL, "ERR Unknown protocol. Use 'file <path>', 'syslog <facility>', or 'tcp <host:port>'", 84);
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
        if (loglevel_debug) {
            printf("Audit: format set to TEXT\n");
        }
        return VALKEYMODULE_OK;
    } else if (strcasecmp(format, "json") == 0) {
        config.format = FORMAT_JSON;
        if (loglevel_debug) {
            printf("Audit: format set to JSON\n");
        }
        return VALKEYMODULE_OK;
    } else if (strcasecmp(format, "csv") == 0) {
        config.format = FORMAT_CSV;
        if (loglevel_debug) {
            printf("Audit: format set to CSV\n");
        }
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
    int pos = 0;
    
    if (config.event_mask == 0) {
        strcpy(event_str, "none");
    } else {
        // Check for all events (more maintainable)
        const int all_events = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS | EVENT_OTHER;
        if (config.event_mask == all_events) {
            strcpy(event_str, "all");
        } else {
            // Build string with position tracking
            if (config.event_mask & EVENT_CONNECTIONS) 
                pos += snprintf(event_str + pos, sizeof(event_str) - pos, "connections,");
        
            if (config.event_mask & EVENT_AUTH) 
                pos += snprintf(event_str + pos, sizeof(event_str) - pos, "auth,");
        
            if (config.event_mask & EVENT_CONFIG) 
                pos += snprintf(event_str + pos, sizeof(event_str) - pos, "config,");
        
            if (config.event_mask & EVENT_KEYS) 
                pos += snprintf(event_str + pos, sizeof(event_str) - pos, "keys,");

            if (config.event_mask & EVENT_OTHER) 
                pos += snprintf(event_str + pos, sizeof(event_str) - pos, "other,");

            // Remove trailing comma
            if (pos > 0) {
                event_str[pos - 1] = '\0';
            }
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
        config.event_mask = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS | EVENT_OTHER;
        if (loglevel_debug) {
            printf("Audit: events set to all\n");
        }
        ValkeyModule_Free(events_copy);
        return VALKEYMODULE_OK;
    } else if (strcasecmp(events_copy, "none") == 0) {
        config.event_mask = 0;
        if (loglevel_debug) {
            printf("Audit: events set to none\n");
        }
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
            snprintf(event_str, sizeof(event_str), "connections,");
        } else if (strcasecmp(token, "auth") == 0) {
            new_mask |= EVENT_AUTH;
            snprintf(event_str, sizeof(event_str), "auth,");
        } else if (strcasecmp(token, "config") == 0) {
            new_mask |= EVENT_CONFIG;
            snprintf(event_str, sizeof(event_str), "config,");
        } else if (strcasecmp(token, "keys") == 0) {
            new_mask |= EVENT_KEYS;
            snprintf(event_str, sizeof(event_str), "keys,");
        } else if (strcasecmp(token, "other") == 0) {
            new_mask |= EVENT_OTHER;
            snprintf(event_str, sizeof(event_str), "other,");    
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
    if (loglevel_debug) {
        printf("Audit: %s\n", details);
    }
    
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
    if (loglevel_debug) {
        printf("Audit: payload set %s\n", details);
    }
    
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
    if (loglevel_debug) {
        printf("Audit: payload set %s\n", details);
    }
    
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

    if (config.always_audit_config) {
        if (loglevel_debug) {
            printf("Audit: always_audit_config set to yes\n");
        }
        return VALKEYMODULE_OK;
    } else {
        if (loglevel_debug) {
            printf("Audit: always_audit_config set to no\n");
        }
        return VALKEYMODULE_OK;
    }

    return VALKEYMODULE_OK;   
}

// Exclusion
ValkeyModuleString *getAuditExclusionRules(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    size_t bufsize = 1024;
    char *buffer = ValkeyModule_Alloc(bufsize);
    if (buffer == NULL) {
        return ValkeyModule_CreateString(NULL, "", 0);
    }
    
    // Build comma-separated list
    buffer[0] = '\0';
    size_t pos = 0;  // Track current position in buffer
    int first = 1;
    ExclusionRule *current = exclusion_rules_head;
    
    while (current != NULL) {
        // Calculate the length needed for this rule entry
        size_t username_len = current->username ? strlen(current->username) : 0;
        size_t ip_len = current->ip_address ? strlen(current->ip_address) : 0;
        size_t entry_len = username_len + ip_len + 2; // +2 for potential @ and comma
        
        // Check if we need to resize the buffer
        if (pos + entry_len + 1 >= bufsize) {
            bufsize *= 2;
            char *new_buffer = ValkeyModule_Realloc(buffer, bufsize);
            if (new_buffer == NULL) {
                ValkeyModule_Free(buffer);
                return ValkeyModule_CreateString(NULL, "", 0);
            }
            buffer = new_buffer;
        }
        
        // Add comma if not the first item
        if (!first) {
            pos += snprintf(buffer + pos, bufsize - pos, ",");
        } else {
            first = 0;
        }
        
        // Add the rule in format "username@ip" or just "username" or "@ip"
        if (current->username) {
            pos += snprintf(buffer + pos, bufsize - pos, "%s", current->username);
        }
        
        if (current->ip_address) {
            pos += snprintf(buffer + pos, bufsize - pos, "@%s", current->ip_address);
        } else if (!current->username) {
            // Edge case: if both are NULL (shouldn't happen)
            pos += snprintf(buffer + pos, bufsize - pos, "@");
        }
        
        current = current->next;
    }
    
    ValkeyModuleString *result = ValkeyModule_CreateString(NULL, buffer, strlen(buffer));
    ValkeyModule_Free(buffer);
    
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
        snprintf(truncated, 177, "%s", new_list);
        truncated[176] = '\0';
        strcat(truncated, "...");
        snprintf(details, sizeof(details), "excluderules=%s", truncated);
    }
    
    if (loglevel_debug) {
        printf("Audit: %s\n", details);
    }

    return VALKEYMODULE_OK;
}

// TCP
// TCP Host getter and setter
ValkeyModuleString *getAuditTcpHost(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    const char *host = config.tcp_host ? config.tcp_host : "";
    return ValkeyModule_CreateString(NULL, host, strlen(host));
}

int setAuditTcpHost(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    size_t len;
    const char *host = ValkeyModule_StringPtrLen(new_val, &len);
    
    // Free existing host if allocated
    if (config.tcp_host) {
        ValkeyModule_Free(config.tcp_host);  
    }
    
    // Allocate and copy new host
    if (len > 0) {
        config.tcp_host = ValkeyModule_Alloc(len + 1);
        if (!config.tcp_host) {
            *err = ValkeyModule_CreateString(NULL, "ERR Failed to allocate memory for TCP host", 41);
            return VALKEYMODULE_ERR;
        }
        memcpy(config.tcp_host, host, len);
        config.tcp_host[len] = '\0';
    } else {
        config.tcp_host = NULL;
    }
    
    if (loglevel_debug) {
        printf("Audit: tcp_host set to %s\n", host);
    }

    return VALKEYMODULE_OK;
}

// TCP Port getter and setter
long long getAuditTcpPort(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    return (long long)config.tcp_port;
}

int setAuditTcpPort(const char *name, long long val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    if (val < 1 || val > 65535) {
        *err = ValkeyModule_CreateString(NULL, "Port must be between 1 and 65535", -1);
        return VALKEYMODULE_ERR;
    }
    
    config.tcp_port = (int)val;
    char audit_msg[64];
    snprintf(audit_msg, sizeof(audit_msg), "tcp_port=%d", config.tcp_port);
    if (loglevel_debug) {
        printf("Audit: %s\n", audit_msg);
    }

    return VALKEYMODULE_OK;
}

// TCP Timeout getter and setter
long long getAuditTcpTimeout(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    return (long long)config.tcp_timeout_ms;
}

int setAuditTcpTimeout(const char *name, long long val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    if (val < 100 || val > 60000) {
        *err = ValkeyModule_CreateString(NULL, "ERR TCP timeout must be between 100 and 60000 milliseconds", 58);
        return VALKEYMODULE_ERR;
    }
    
    config.tcp_timeout_ms = (int)val;
    
    char audit_msg[64];
    snprintf(audit_msg, sizeof(audit_msg), "tcp_timeout_ms=%d", config.tcp_timeout_ms);
    if (loglevel_debug) {
        printf("Audit: %s\n", audit_msg);
    }

    return VALKEYMODULE_OK;
}

// TCP Retry Interval getter and setter
long long getAuditTcpRetryInterval(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);

    return (long long)config.tcp_retry_interval_ms;
}

int setAuditTcpRetryInterval(const char *name, long long interval, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    if (interval < 100 || interval > 300000) {
        *err = ValkeyModule_CreateString(NULL, "ERR TCP retry interval must be between 100 and 300000 milliseconds", 66);
        return VALKEYMODULE_ERR;
    }
    
    config.tcp_retry_interval_ms = (int)interval;
    
    char audit_msg[64];
    snprintf(audit_msg, sizeof(audit_msg), "tcp_retry_interval_ms=%d", config.tcp_retry_interval_ms);
    
    if (loglevel_debug) {
        printf("Audit: %s\n", audit_msg);
    }
    return VALKEYMODULE_OK;
}

// TCP Max Retries getter and setter
long long getAuditTcpMaxRetries(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    return (long long)config.tcp_max_retries;
}

int setAuditTcpMaxRetries(const char *name, long long retries, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
   
   if (retries < 0 || retries > 100) {
        *err = ValkeyModule_CreateString(NULL, "ERR TCP max retries must be between 0 and 100", 45);
        return VALKEYMODULE_ERR;
    }
    
    config.tcp_max_retries = (int)retries;
    
    char audit_msg[64];
    snprintf(audit_msg, sizeof(audit_msg), "tcp_max_retries=%d", config.tcp_max_retries);
    if (loglevel_debug) {
        printf("Audit: %s\n", audit_msg);
    }
    return VALKEYMODULE_OK;
}

// TCP Reconnect On Failure getter and setter
int getAuditTcpReconnectOnFailure(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    return config.tcp_reconnect_on_failure;
}

int setAuditTcpReconnectOnFailure(const char *name, int new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);

    config.tcp_reconnect_on_failure = new_val;
    
    if (config.tcp_reconnect_on_failure) {
        if (loglevel_debug) {
            printf("Audit: tcp_reconnect_on_failure set to yes\n");
        }

        return VALKEYMODULE_OK;
    } else {
        if (loglevel_debug) {
            printf("Audit: tcp_reconnect_on_failure set to no\n");
        }
        return VALKEYMODULE_OK;
    }
}

// TCP Buffer On Disconnect getter and setter
int getAuditTcpBufferOnDisconnect(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    return config.tcp_buffer_on_disconnect;
}

int setAuditTcpBufferOnDisconnect(const char *name, int new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);

    config.tcp_buffer_on_disconnect = new_val;
    
    if (config.tcp_buffer_on_disconnect) {
        if (loglevel_debug) {
            printf("Audit: tcp_buffer_on_disconnect set to yes\n");
        }
        return VALKEYMODULE_OK;
    } else {
        if (loglevel_debug) {
            printf("Audit: tcp_buffer_on_disconnect set to no\n");
        }
        return VALKEYMODULE_OK;
    }
}

ValkeyModuleString *getAuditBufferSize(const char *name, void *privdata) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(privdata);
    
    char size_str[32];
    snprintf(size_str, sizeof(size_str), "%zu", config.buffer_size);
    return ValkeyModule_CreateString(NULL, size_str, strlen(size_str));
}

int setAuditBufferSize(const char *name, ValkeyModuleString *new_val, void *privdata, ValkeyModuleString **err) {
    VALKEYMODULE_NOT_USED(name);
    VALKEYMODULE_NOT_USED(new_val);
    VALKEYMODULE_NOT_USED(privdata);
    VALKEYMODULE_NOT_USED(err);

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
    const char *username = "unknown"; // Default value
    char *temp_username = NULL;       // For tracking allocated memory
    
    if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED) {
        // Client connected - get and store username
        ValkeyModuleString *user_str = ValkeyModule_GetClientUserNameById(ctx, ci->id);

        if (user_str != NULL) {
            size_t user_len;
            const char *user_ptr = ValkeyModule_StringPtrLen(user_str, &user_len);

            // Make a temporary copy for our use in this function
            temp_username = ValkeyModule_Alloc(user_len + 1);
            if (temp_username == NULL) {
                // Handle memory allocation failure
                ValkeyModule_Log(ctx, "warning", "Failed to allocate memory for username");
                ValkeyModule_FreeString(ctx, user_str);
                return; // Or some other error handling
            }
            
            snprintf(temp_username, user_len + 1, "%s", user_ptr);
            temp_username[user_len] = '\0'; // Null-terminate the copy
            username = temp_username;       // Use our copy for the audit message

            // Check if client should be excluded from audit based on username and IP
            int no_audit = isClientExcluded(username, ci->addr);
            
            // Store username and IP in hash table
            storeClientInfo(ci->id, username, ci->addr, ci->port, no_audit, 0);

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
            storeClientInfo(ci->id, username, ci->addr, ci->port, 0, 0);
        }
    } else if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED) {
        // For disconnection, get the client info from the hash table
        ClientUsernameEntry *entry = getClientEntry(ci->id);
        if (entry != NULL) {
            // Make a copy of the username before we remove it from the hash
            if (entry->username != NULL) {
                temp_username = ValkeyModule_Strdup(entry->username);
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
    
    logAuditEvent("CONNECTION", event_type, buffer, username, ci->addr, ci->port, EVENT_SUCCESS);
    
    // Clean up our temporary memory
    if (temp_username != NULL) {
        ValkeyModule_Free(temp_username);
    }
}

int authLoggerCallback(ValkeyModuleCtx *ctx, ValkeyModuleString *username, 
                       ValkeyModuleString *password, ValkeyModuleString **err) {

    VALKEYMODULE_NOT_USED(password);
    VALKEYMODULE_NOT_USED(err);

    if (config.enabled != 1) return VALKEYMODULE_AUTH_NOT_HANDLED;

    // Extract username
    size_t username_len;
    const char *username_str = ValkeyModule_StringPtrLen(username, &username_len);

    // Get client information
    uint64_t client_id = ValkeyModule_GetClientId(ctx);
    char client_info[256] = "unknown";
    char client_ip[128] = "unknown"; 
    int client_port = 0;

    // Try to get client info
    ValkeyModuleClientInfo client = VALKEYMODULE_CLIENTINFO_INITIALIZER_V1;
    if (ValkeyModule_GetClientInfoById(&client, client_id) == VALKEYMODULE_OK) {
        snprintf(client_info, sizeof(client_info), "%s:%d", client.addr, client.port);
        snprintf(client_ip, sizeof(client_ip), "%s", client.addr);
        client_port = client.port;
    }

    // Get current timestamp
    mstime_t auth_timestamp = getCurrentTimestampMs();

    // Format audit message for auth attempt
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), 
                "Authentication attempt for username: %s from client #%llu (%s)",
                 username_str, (unsigned long long)client_id, client_info);

    // Log the auth attempt
    logAuditEvent("AUTH", "AUTH", buffer, username_str, client_ip, client_port, EVENT_ATTEMPT);

    // Check if client should be excluded based on username and IP
    int no_audit = isClientExcluded(username_str, client_ip);
    
    // Store client info with auth timestamp
    storeClientInfo(client_id, username_str, client_ip, client_port, no_audit, auth_timestamp);

    // Schedule a timer to check the actual auth result
    if (scheduleAuthResultCheck(ctx, client_id) != VALKEYMODULE_OK) {
        // If timer creation fails, log an error
        logAuditEvent("AUTH", "ERROR", "Failed to schedule auth result check", username_str, client_ip, client_port, EVENT_ERROR);
    }

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
    char *username = "unknown";
    char *ip_address = "unknown";
    int client_port = 0;
    ClientUsernameEntry *entry = getClientEntry(client);
    
    // Always get client info if available, for logging purposes
    if (entry != NULL) {
        username = entry->username;
        ip_address = entry->ip_address;
        no_audit = entry->no_audit;
        client_port = entry->client_port;
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
    int is_other_cmd =0;
    
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
        // If not a key command but OTHER auditing is enabled
        if (!is_key_cmd && (config.event_mask & EVENT_OTHER)) {
            category_match = 1;
            is_other_cmd =1;
        }
    }
    
    // Skip if command category doesn't match any enabled audit categories
    if (!category_match) {
        return;
    }
    
    // Build command details including args
    char command_str[256] = "";
    snprintf(command_str, sizeof(command_str), "%s", cmd_str);
    command_str[sizeof(command_str) - 1] = '\0';
    
    // Build details buffer
    char details[2048] = "";
    char client_info[128] = "";
    char username_info[128] = "";
    char ip_info[128] = "";
    
    // Add client ID to details
    if (client) {
        snprintf(client_info, sizeof(client_info), "client_id=%llu", client);
        snprintf(details + strlen(details), sizeof(details) - strlen(details), "%s", client_info);
    }
    if (username) {
        snprintf(username_info, sizeof(username_info), " username=%s", username);
        snprintf(details + strlen(details), sizeof(details) - strlen(details), "%s", username_info);
    }
    if (ip_address) {
        snprintf(ip_info, sizeof(ip_info), " ip=%s", ip_address);
        snprintf(details + strlen(details), sizeof(details) - strlen(details), "%s", ip_info);
    }
    
    // For CONFIG commands, add the subcommand and parameter
    if (is_config_cmd) {
        const ValkeyModuleString *subcmd_arg = ValkeyModule_CommandFilterArgGet(filter, 1);
        if (subcmd_arg != NULL) {
            size_t subcmd_len;
            const char *subcmd_str = ValkeyModule_StringPtrLen(subcmd_arg, &subcmd_len);
            
            size_t details_len = strlen(details);
            if (details_len > 0) {
                snprintf(details + details_len, sizeof(details) - details_len, " ");
                details_len += 1; 
            }
            
            snprintf(details + details_len, sizeof(details) - details_len, "subcommand=");
            details_len += 11; 
            
            snprintf(details + details_len, sizeof(details) - details_len, "%s", subcmd_str);
            details_len += strlen(subcmd_str);
            
            // Get parameter for GET/SET subcmd
            if ((strcasecmp(subcmd_str, "get") == 0 || strcasecmp(subcmd_str, "set") == 0)) {
                const ValkeyModuleString *param_arg = ValkeyModule_CommandFilterArgGet(filter, 2);
                if (param_arg != NULL) {
                    size_t param_len;
                    const char *param_str = ValkeyModule_StringPtrLen(param_arg, &param_len);
                    
                    snprintf(details + details_len, sizeof(details) - details_len, " param=");
                    details_len += 7; 
                    
                    snprintf(details + details_len, sizeof(details) - details_len, "%s", param_str);
                    // No need to update details_len here if it's not used further
                }
            }
        }
    }
    // For AUTH commands, add redacted password
    else if (is_auth_cmd) {
        size_t details_len = strlen(details);

        if (details_len > 0) {
            snprintf(details + details_len, sizeof(details) - details_len, " ");
            details_len += 1;
        }
        
        snprintf(details + details_len, sizeof(details) - details_len, "password=<REDACTED>");
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
                
                size_t details_len = strlen(details);

                if (details_len > 0) {
                    snprintf(details + details_len, sizeof(details) - details_len, " ");
                    details_len += 1;
                }
                
                snprintf(details + details_len, sizeof(details) - details_len, "key=");
                details_len += 4;
                
                snprintf(details + details_len, sizeof(details) - details_len, "%s", key_str);            }
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
                    size_t details_len = strlen(details);

                    if (details_len > 0) {
                        snprintf(details + details_len, sizeof(details) - details_len, " ");
                        details_len += 1; 
                    }
                    
                    snprintf(details + details_len, sizeof(details) - details_len, "payload=");
                    details_len += 8; 
                    
                    // Copy payload up to max length
                    size_t remaining = sizeof(details) - details_len - 1;
                    size_t copy_len = payload_len < remaining ? payload_len : remaining;
                    
                    // For a potentially non-null-terminated string, use precision in the format string
                    snprintf(details + details_len, sizeof(details) - details_len, "%.*s", (int)copy_len, payload_str);
                    details_len += copy_len;
                    
                    // Indicate truncation if needed
                    if (payload_len > config.max_payload_size) {
                        snprintf(details + details_len, sizeof(details) - details_len, "... (truncated)");
                    }                
                }
            }
        }
    }
    // For OTHER commands, add basic argument information
    else if (is_other_cmd) {
        // Add first few arguments for context
        int argc = ValkeyModule_CommandFilterArgsCount(filter);
        int max_args_to_log = 3; 
        
        for (int i = 1; i < argc && i <= max_args_to_log; i++) {
            const ValkeyModuleString *arg = ValkeyModule_CommandFilterArgGet(filter, i);
            if (arg != NULL) {
                size_t arg_len;
                const char *arg_str = ValkeyModule_StringPtrLen(arg, &arg_len);
                
                size_t details_len = strlen(details);
                if (details_len > 0) {
                    snprintf(details + details_len, sizeof(details) - details_len, " ");
                    details_len += 1;
                }
                
                // Limit argument length to prevent log overflow
                size_t max_arg_len = 50;
                if (arg_len > max_arg_len) {
                    snprintf(details + details_len, sizeof(details) - details_len, "arg%d=%.50s...", i, arg_str);
                } else {
                    snprintf(details + details_len, sizeof(details) - details_len, "arg%d=%.*s", i, (int)arg_len, arg_str);
                }
            }
        }
        
        // Indicate if there are more arguments
        if (argc > max_args_to_log + 1) {
            size_t details_len = strlen(details);
            snprintf(details + details_len, sizeof(details) - details_len, " (and %d more args)", argc - max_args_to_log - 1);
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
    } else if (is_other_cmd) {
        category_str = "OTHER";
    } else { // Should not happen
        category_str = "COMMAND";
    }
    
    // Log the audit event
    logAuditEvent(category_str, command_str, details, username, ip_address, client_port, EVENT_EXECUTE);
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
    config.file_path = ValkeyModule_Strdup("/var/log/valkey/audit.log");
    
    // Initialize TCP defaults
    config.tcp_host = ValkeyModule_Strdup("127.0.0.1");  // Default to localhost
    config.tcp_port = 514;                  // Default to traditional syslog port
    config.tcp_timeout_ms = 5000;           // 5 seconds connect timeout
    config.tcp_retry_interval_ms = 1000;    // 1 second between retries
    config.tcp_max_retries = 3;             // Retry 3 times by default
    config.tcp_reconnect_on_failure = 1;    // Enable automatic reconnection
    config.tcp_buffer_on_disconnect = 1;    // Buffer logs during disconnection
    
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
        else if (i < argc-1 && strcasecmp(arg, "always_audit_config") == 0) {
            const char *always_audit_config = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
        
            if (strcasecmp(always_audit_config, "yes") == 0 || strcasecmp(always_audit_config, "1") == 0) {
                config.always_audit_config = 1;
            } else if (strcasecmp(always_audit_config, "no") == 0 || strcasecmp(always_audit_config, "0") == 0){
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
                    config.file_path = ValkeyModule_Strdup(ValkeyModule_StringPtrLen(argv[i+1], NULL));
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
            } else if (strcasecmp(protocol, "tcp") == 0) {
                config.protocol = PROTOCOL_TCP;
                
                // Check if there's another argument available for tcp host:port
                if (i < argc-1) {
                    const char *hostport = ValkeyModule_StringPtrLen(argv[i+1], NULL);
                    i++;  // Skip the host:port argument
                    
                    // Parse host:port format
                    char *colon = strchr(hostport, ':');
                    if (colon) {
                        // Split host and port
                        size_t host_len = colon - hostport;
                        config.tcp_host = ValkeyModule_Calloc(1, host_len + 1);
                        snprintf(config.tcp_host, host_len + 1, "%s", hostport);
                        
                        // Parse port
                        char *endptr;
                        long port = strtol(colon + 1, &endptr, 10);
                        if (*endptr != '\0' || port <= 0 || port > 65535) {
                            ValkeyModule_Log(ctx, "warning", 
                                "Invalid TCP port '%s', using default port %d", 
                                colon + 1, config.tcp_port);
                        } else {
                            config.tcp_port = (int)port;
                        }
                    } else {
                        // Just a hostname without port
                        config.tcp_host = ValkeyModule_Strdup(hostport);
                    }
                } else {
                    ValkeyModule_Log(ctx, "warning", 
                        "Missing host:port for TCP protocol, using default %s:%d",
                        config.tcp_host, config.tcp_port);
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
            
            char *events_copy = ValkeyModule_Strdup(events);
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
                } else if (strcasecmp(token, "other") == 0) {
                    config.event_mask |= EVENT_OTHER;
                } else if (strcasecmp(token, "all") == 0) {
                    config.event_mask = EVENT_CONNECTIONS | EVENT_AUTH | EVENT_CONFIG | EVENT_KEYS | EVENT_OTHER;
                } else if (strcasecmp(token, "none") == 0) {
                    config.event_mask = 0;
                } else {
                    ValkeyModule_Log(ctx, "warning", "Unknown event type '%s', ignoring", token);
                }
                
                token = strtok(NULL, ",");
            }
            
            ValkeyModule_Free(events_copy);
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
        // TCP-specific configuration options
        else if (i < argc-1 && strcasecmp(arg, "tcp_timeout") == 0) {
            const char *timeout_str = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
            
            char *endptr;
            long timeout = strtol(timeout_str, &endptr, 10);
            
            if (*endptr != '\0' || timeout <= 0) {
                ValkeyModule_Log(ctx, "warning", "Invalid TCP timeout '%s', using default", timeout_str);
            } else {
                config.tcp_timeout_ms = (int)timeout;
            }
        }
        else if (i < argc-1 && strcasecmp(arg, "tcp_retry_interval") == 0) {
            const char *interval_str = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
            
            char *endptr;
            long interval = strtol(interval_str, &endptr, 10);
            
            if (*endptr != '\0' || interval < 0) {
                ValkeyModule_Log(ctx, "warning", "Invalid TCP retry interval '%s', using default", interval_str);
            } else {
                config.tcp_retry_interval_ms = (int)interval;
            }
        }
        else if (i < argc-1 && strcasecmp(arg, "tcp_max_retries") == 0) {
            const char *retries_str = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
            
            char *endptr;
            long retries = strtol(retries_str, &endptr, 10);
            
            if (*endptr != '\0' || retries < 0) {
                ValkeyModule_Log(ctx, "warning", "Invalid TCP max retries '%s', using default", retries_str);
            } else {
                config.tcp_max_retries = (int)retries;
            }
        }
        else if (i < argc-1 && strcasecmp(arg, "tcp_reconnect") == 0) {
            const char *reconnect = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
            
            if (strcasecmp(reconnect, "yes") == 0 || strcasecmp(reconnect, "1") == 0) {
                config.tcp_reconnect_on_failure = 1;
            } else if (strcasecmp(reconnect, "no") == 0 || strcasecmp(reconnect, "0") == 0) {
                config.tcp_reconnect_on_failure = 0;
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown value for tcp_reconnect '%s', using default", reconnect);
            }
        }
        else if (i < argc-1 && strcasecmp(arg, "tcp_buffer") == 0) {
            const char *buffer = ValkeyModule_StringPtrLen(argv[i+1], NULL);
            i++;
            
            if (strcasecmp(buffer, "yes") == 0 || strcasecmp(buffer, "1") == 0) {
                config.tcp_buffer_on_disconnect = 1;
            } else if (strcasecmp(buffer, "no") == 0 || strcasecmp(buffer, "0") == 0) {
                config.tcp_buffer_on_disconnect = 0;
            } else {
                ValkeyModule_Log(ctx, "warning", "Unknown value for tcp_buffer '%s', using default", buffer);
            }
        }
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

    // Init server_hostname variable
    if (gethostname(server_hostname, sizeof(server_hostname)) != 0) {
        ValkeyModule_Log(ctx, "notice", "Audit error getting hostname: %s\n", strerror(errno));
    }

    // Get the server loglevel
    ValkeyModuleCallReply *reply = ValkeyModule_Call(ctx, "CONFIG", "cc", "GET", "loglevel");
    if (reply != NULL && ValkeyModule_CallReplyType(reply) == VALKEYMODULE_REPLY_ARRAY) {
        size_t len = ValkeyModule_CallReplyLength(reply);
        if (len >= 2) {
            ValkeyModuleCallReply *value_reply = ValkeyModule_CallReplyArrayElement(reply, 1); // Fixed typo
            if (ValkeyModule_CallReplyType(value_reply) == VALKEYMODULE_REPLY_STRING) {
                size_t str_len;
                const char *log_level_str = ValkeyModule_CallReplyStringPtr(value_reply, &str_len);
                if (strncmp(log_level_str, "debug", str_len) == 0) {
                    loglevel_debug = 1;
                } else {
                    loglevel_debug = 0;
                }
            }
        }
    }
    ValkeyModule_FreeCallReply(reply);

    // Initialize audit logging system
    if (initAuditLog(&config) != 0) {
        ValkeyModule_Log(ctx, "warning", "Failed to initialize audit logging system");
        // Clean up any resources and potentially return error
        if (config.file_fd != -1) close(config.file_fd);
        return VALKEYMODULE_ERR;
    }
    ValkeyModule_Log(ctx, "notice", "Audit logging system initialized successfully");

    // Initialize the audit module config with passed arguments
    if (initAuditModule(ctx, argv, argc) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }  

    // Initialize hash table for client usernames
    for (int i = 0; i < USERNAME_HASH_SIZE; i++) {
        username_hash[i] = NULL;
    }

    // Register module configurations
    char default_protocol[256];
    if (config.protocol == PROTOCOL_FILE) {
        snprintf(default_protocol, sizeof(default_protocol), "file %s", config.file_path);
    }
    else if (config.protocol == PROTOCOL_SYSLOG) {       
        char facility[12];
        if (config.syslog_facility == LOG_LOCAL0) snprintf(facility, sizeof(facility), "local0");
        else if (config.syslog_facility == LOG_LOCAL1) snprintf(facility, sizeof(facility), "local1");
        else if (config.syslog_facility == LOG_LOCAL2) snprintf(facility, sizeof(facility), "local2");
        else if (config.syslog_facility == LOG_LOCAL3) snprintf(facility, sizeof(facility), "local3");
        else if (config.syslog_facility == LOG_LOCAL4) snprintf(facility, sizeof(facility), "local4");
        else if (config.syslog_facility == LOG_LOCAL5) snprintf(facility, sizeof(facility), "local5");
        else if (config.syslog_facility == LOG_LOCAL6) snprintf(facility, sizeof(facility), "local6");
        else if (config.syslog_facility == LOG_LOCAL7) snprintf(facility, sizeof(facility), "local7");
        else if (config.syslog_facility == LOG_USER) snprintf(facility, sizeof(facility), "user");
        else if (config.syslog_facility == LOG_DAEMON) snprintf(facility, sizeof(facility), "daemon");
        else {
            ValkeyModule_Log(ctx, "warning", "Unknown syslog facility '%s', using default", facility);
        }
        snprintf(default_protocol, sizeof(default_protocol), "syslog %s", facility);
    }
    else if (config.protocol == PROTOCOL_TCP) {       
        snprintf(default_protocol, sizeof(default_protocol), "tcp %s:%d", config.tcp_host, config.tcp_port );
    }
    else {
        // default to 
        snprintf(default_protocol, sizeof(default_protocol), "file %s", config.file_path);
    }

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
    int pos = 0;
    
    if (config.event_mask & EVENT_CONNECTIONS) {
        pos += snprintf(default_events + pos, sizeof(default_events) - pos, "connections,");
    }
    if (config.event_mask & EVENT_AUTH) {
        pos += snprintf(default_events + pos, sizeof(default_events) - pos, "auth,");
    }
    if (config.event_mask & EVENT_CONFIG) {
        pos += snprintf(default_events + pos, sizeof(default_events) - pos, "config,");
    }
    if (config.event_mask & EVENT_KEYS) {
        pos += snprintf(default_events + pos, sizeof(default_events) - pos, "keys,");
    }
    if (config.event_mask & EVENT_OTHER) {
        pos += snprintf(default_events + pos, sizeof(default_events) - pos, "other,");
    }
    
    // Remove trailing comma if any events were added
    if (pos > 0) {
        default_events[pos - 1] = '\0';
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

    const char* default_tcp_host = config.tcp_host ? config.tcp_host : "";
    if (ValkeyModule_RegisterStringConfig(ctx, "tcp_host", default_tcp_host, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditTcpHost, setAuditTcpHost, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register TCP port configuration
    if (ValkeyModule_RegisterNumericConfig(ctx, "tcp_port", config.tcp_port,
           VALKEYMODULE_CONFIG_DEFAULT,
           1,            // Minimum port
           65535,        // Maximum port
           getAuditTcpPort, setAuditTcpPort, 
           NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register TCP timeout configuration
    if (ValkeyModule_RegisterNumericConfig(ctx, "tcp_timeout_ms", config.tcp_timeout_ms,
           VALKEYMODULE_CONFIG_DEFAULT,
           100,          // Minimum 100ms
           60000,        // Maximum 60 seconds
           getAuditTcpTimeout, setAuditTcpTimeout, 
           NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register TCP retry interval configuration
    if (ValkeyModule_RegisterNumericConfig(ctx, "tcp_retry_interval_ms", config.tcp_retry_interval_ms,
           VALKEYMODULE_CONFIG_DEFAULT,
           100,          // Minimum 100ms
           300000,       // Maximum 5 minutes
           getAuditTcpRetryInterval, setAuditTcpRetryInterval, 
           NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register TCP max retries configuration
    if (ValkeyModule_RegisterNumericConfig(ctx, "tcp_max_retries", config.tcp_max_retries,
           VALKEYMODULE_CONFIG_DEFAULT,
           0,            // No retries
           100,          // Maximum retries
           getAuditTcpMaxRetries, setAuditTcpMaxRetries, 
           NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register TCP reconnect on failure configuration
    if (ValkeyModule_RegisterBoolConfig(ctx, "tcp_reconnect_on_failure", config.tcp_reconnect_on_failure, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditTcpReconnectOnFailure, setAuditTcpReconnectOnFailure, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register TCP buffer on disconnect configuration
    if (ValkeyModule_RegisterBoolConfig(ctx, "tcp_buffer_on_disconnect", config.tcp_buffer_on_disconnect, 
            VALKEYMODULE_CONFIG_DEFAULT,
            getAuditTcpBufferOnDisconnect, setAuditTcpBufferOnDisconnect, 
            NULL, NULL) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }

    // Register buffer size configuration
    //if (ValkeyModule_RegisterNumericConfig(ctx, "buffer_size", config.buffer_size,
    //       VALKEYMODULE_CONFIG_DEFAULT,
    //       1024,         // Minimum 1KB
    //       LLONG_MAX,    // Maximum value
    //       getAuditBufferSize, setAuditBufferSize, 
    //       NULL, NULL) == VALKEYMODULE_ERR) {
    //    return VALKEYMODULE_ERR;
    //}


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
    
    // Shutdown audit logging system
    // flushes any pending writes and waits for background jobs to complete
    shutdownAuditLog();

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
        ValkeyModule_Free(config.file_path);
        config.file_path = NULL;
    }
    
    ValkeyModule_Log(ctx, "notice", "Audit logging system shut down successfully");
    
    return VALKEYMODULE_OK;
}