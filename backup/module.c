#include "valkeymodule.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_LOG_SIZE 10000
#define MAX_BUFFER_SIZE 1024

static ValkeyModuleCommandFilter *filter;

/* Module configuration */
typedef struct ConnectionAuditConfig {
    int log_auth_failures;  /* 1 = log auth failures, 0 = don't log */
    char *log_file;         /* Path to the log file when not storing in Valkey */
    size_t max_log_size;    /* Number of entries to buffer before writing to file */
} ConnectionAuditConfig;

/* Global configuration with defaults */
static ConnectionAuditConfig config = {
    .log_auth_failures = 1,
    .log_file = NULL,
    .max_log_size = MAX_LOG_SIZE
};

/* Connection stats */
typedef struct ConnectionStats {
    size_t total_connections;
    size_t active_connections;
    size_t auth_failures;
    time_t start_time;
} ConnectionStats;

static ConnectionStats stats = {0};

/* Helper function to get formatted timestamp */
static void getTimeStr(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}

/* Helper function to write audit log to file */
static void writeToFile(const char *message) {
    if (!config.log_file) return;
    
    FILE *f = fopen(config.log_file, "a");
    if (!f) {
        return;
    }
    
    char timestamp[32];
    getTimeStr(timestamp, sizeof(timestamp));
    
    fprintf(f, "[%s] %s\n", timestamp, message);
    fclose(f);
}

/* Helper function to log an audit message */
static void logAuditMessage(ValkeyModuleCtx *ctx, const char *message) {
    /* Log to Valkey internal log for debugging */
    ValkeyModule_Log(ctx, "notice", "CONNECTION AUDIT: %s", message);
    
    writeToFile(message);
}

/* Helper function to format client information into a detail string */
static void formatClientDetails(ValkeyModuleClientInfo *ci, char *buffer, size_t buffer_size) {
    char flags_str[256] = "";
    
    /* Build flags description */
    if (ci->flags & VALKEYMODULE_CLIENTINFO_FLAG_SSL)
        strcat(flags_str, "SSL,");
    if (ci->flags & VALKEYMODULE_CLIENTINFO_FLAG_PUBSUB)
        strcat(flags_str, "PubSub,");
    if (ci->flags & VALKEYMODULE_CLIENTINFO_FLAG_BLOCKED)
        strcat(flags_str, "Blocked,");
    if (ci->flags & VALKEYMODULE_CLIENTINFO_FLAG_TRACKING)
        strcat(flags_str, "Tracking,");
    if (ci->flags & VALKEYMODULE_CLIENTINFO_FLAG_UNIXSOCKET)
        strcat(flags_str, "UnixSocket,");
    if (ci->flags & VALKEYMODULE_CLIENTINFO_FLAG_MULTI)
        strcat(flags_str, "Multi,");
    
    /* Remove trailing comma if any flags were set */
    size_t len = strlen(flags_str);
    if (len > 0) {
        flags_str[len-1] = '\0';
    } else {
        strcpy(flags_str, "None");
    }
    
    /* Format full client details */
    snprintf(buffer, buffer_size, 
        "id=%llu addr=%s:%d db=%d flags=[%s]",
        (unsigned long long)ci->id, 
        ci->addr[0] ? ci->addr : "unknown", 
        ci->port,
        ci->db,
        flags_str);
}

/* Get client type string */
static const char* getClientTypeStr(ValkeyModuleClientInfo *ci) {
    if (ci->flags & (1ULL << 0)) return "normal";
    if (ci->flags & (1ULL << 1)) return "replica";
    if (ci->flags & (1ULL << 2)) return "pubsub";
    /* Add more client types as needed */
    return "unknown";
}

/* Command to get connection statistics */
int GetConnectionStats_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    ValkeyModule_ReplyWithArray(ctx, 5);
    
    /* Calculate uptime */
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

/* Command to configure the connection audit module */
int ConfigConnectionAudit_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (argc < 2 || argc % 2 != 0) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    for (int i = 1; i < argc; i += 2) {
        const char *option = ValkeyModule_StringPtrLen(argv[i], NULL);
        const char *value = ValkeyModule_StringPtrLen(argv[i+1], NULL);
        
        if (strcasecmp(option, "log_auth_failures") == 0) {
            config.log_auth_failures = atoi(value);
        }
        else if (strcasecmp(option, "log_file") == 0) {
            if (config.log_file) {
                ValkeyModule_Free(config.log_file);
            }
            config.log_file = ValkeyModule_Strdup(value);
        }
        else if (strcasecmp(option, "max_log_size") == 0) {
            config.max_log_size = atoi(value);
            if (config.max_log_size < 100) config.max_log_size = 100;
        }
        else {
            return ValkeyModule_ReplyWithError(ctx, "ERR invalid option");
        }
    }
    
    return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
}

/* Reset connection statistics */
int ResetConnectionStats_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    /* Keep active_connections as is, since that's current state */
    int active = stats.active_connections;
    
    /* Reset stats */
    memset(&stats, 0, sizeof(stats));
    stats.active_connections = active;
    stats.start_time = time(NULL);
    
    return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
}

/* Command to get the current connection audit configuration */
int GetConnectionAuditConfig_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    /* Reply with a flat array of key-value pairs */
    ValkeyModule_ReplyWithArray(ctx, 6);  /* 3 config parameters * 2 */
    
    ValkeyModule_ReplyWithSimpleString(ctx, "log_auth_failures");
    ValkeyModule_ReplyWithLongLong(ctx, config.log_auth_failures);
    
    ValkeyModule_ReplyWithSimpleString(ctx, "max_log_size");
    ValkeyModule_ReplyWithLongLong(ctx, config.max_log_size);
    
    ValkeyModule_ReplyWithSimpleString(ctx, "log_file");
    if (config.log_file) {
        ValkeyModule_ReplyWithSimpleString(ctx, config.log_file);
    } else {
        ValkeyModule_ReplyWithNull(ctx);
    }
    
    return VALKEYMODULE_OK;
}

/* Client state change callback. */
void clientChangeCallback(ValkeyModuleCtx *ctx, ValkeyModuleEvent e, uint64_t sub, void *data)
{
    VALKEYMODULE_NOT_USED(e);
    char buffer[1024];

    ValkeyModuleClientInfo *event_ci = data;
    
    if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED) {
        /* Track connection stat */
        stats.total_connections++;
        stats.active_connections++;
        
        /* Fallback if we can't get full client info */
        snprintf(buffer, sizeof(buffer), 
            "Client connected: id=%llu addr=%s:%d",
            (unsigned long long)event_ci->id, 
            event_ci->addr[0] ? event_ci->addr : "unknown", 
            event_ci->port);
    } 
    else if (sub == VALKEYMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED) {
        /* Update stats */
        if (stats.active_connections > 0) {
            stats.active_connections--;
        }
        
        snprintf(buffer, sizeof(buffer), 
            "Client disconnected: id=%llu addr=%s:%d", 
            (unsigned long long)event_ci->id, 
            event_ci->addr[0] ? event_ci->addr : "unknown", 
            event_ci->port);
    }
    logAuditMessage(ctx, buffer);
}

/* Auth command filter to log authentication attempts */
void CommandFilter_AuthCommandFilter(ValkeyModuleCommandFilterCtx *filter)
{
    int argc = ValkeyModule_CommandFilterArgsCount(filter);

    if (argc >= 1) {
        const ValkeyModuleString *arg = ValkeyModule_CommandFilterArgGet(filter, 0);
        size_t arg_len;
        const char *arg_str = ValkeyModule_StringPtrLen(arg, &arg_len);

        if (arg_len == 4 && !strncasecmp(arg_str, "AUTH", 4)) {
          /* Build debug string with AUTH arguments */
          char debug_str[MAX_BUFFER_SIZE] = "";
          strcat(debug_str, "AUTH");

          if (argc >= 2) {
            const ValkeyModuleString *username_arg = ValkeyModule_CommandFilterArgGet(filter, 1);
            size_t username_len;
            const char *username = ValkeyModule_StringPtrLen(username_arg, &username_len);
            strcat(debug_str, " ");
            strncat(debug_str, username, username_len);
            
            /* Add placeholder for password if provided (arg position 2) */
            if (argc >= 3) {
              const ValkeyModuleString *pwd_arg = ValkeyModule_CommandFilterArgGet(filter, 2);
              size_t pwd_len;
              const char *pwd = ValkeyModule_StringPtrLen(pwd_arg, &pwd_len);
              strcat(debug_str, " ");
              strncat(debug_str, pwd, pwd_len);
            }
          }

          printf("DEBUG: AUTH Command: %s, ",debug_str);      
        }
    }
}

/* This function must be present on each Valkey module. It is used in order to
 * register the commands into the Valkey server. */
int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (ValkeyModule_Init(ctx,"connaudit",1,VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) 
        return VALKEYMODULE_ERR;

    /* Process module arguments */
    for (int i = 0; i < argc; i++) {
        const char *arg = ValkeyModule_StringPtrLen(argv[i], NULL);
        
        if (strncmp(arg, "log_file=", 9) == 0) {
            config.log_file = ValkeyModule_Strdup(arg + 9);
        }
    }

    /* Default log file if not specified and */
    if (!config.log_file) {
        config.log_file = ValkeyModule_Strdup("/var/log/valkey-connections.log");
    }
    
    /* Initialize stats */
    stats.start_time = time(NULL);

    /* Register commands */
    if (ValkeyModule_CreateCommand(ctx, "connaudit.stats", 
                               GetConnectionStats_ValkeyCommand,
                               "readonly", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;
        
    if (ValkeyModule_CreateCommand(ctx, "connaudit.resetstats", 
                               ResetConnectionStats_ValkeyCommand,
                               "admin", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    if (ValkeyModule_CreateCommand(ctx, "connaudit.getconfig", 
            GetConnectionAuditConfig_ValkeyCommand,
            "readonly", 0, 0, 0) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

    /* Subscribe to client connection/disconnection events */
    if (ValkeyModule_SubscribeToServerEvent(ctx,
        ValkeyModuleEvent_ClientChange, clientChangeCallback) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;

       
    if ((filter = ValkeyModule_RegisterCommandFilter(ctx, CommandFilter_AuthCommandFilter, 
            VALKEYMODULE_CMDFILTER_NOSELF))== NULL) 
        return VALKEYMODULE_ERR;    
    
    return VALKEYMODULE_OK;

}

/* Clean up when module is unloaded */
int ValkeyModule_OnUnload(ValkeyModuleCtx *ctx) {
    VALKEYMODULE_NOT_USED(ctx);
    
    if (config.log_file) {
        ValkeyModule_Free(config.log_file);
    }
    
    return VALKEYMODULE_OK;
}
