#include "valkeymodule.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// Auth logging callback function
int auth_logger_callback(ValkeyModuleCtx *ctx, ValkeyModuleString *username, 
                        ValkeyModuleString *password, ValkeyModuleString **err) {
    // Get current timestamp
    time_t now;
    time(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Extract username and password
    size_t username_len;
    const char *user = ValkeyModule_StringPtrLen(username, &username_len);
    const char *pwd = ValkeyModule_StringPtrLen(password, NULL);

    // Create log message that includes the password
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Auth attempt at %s: User '%.*s', Password '%s'", 
       time_str, (int)username_len, user, pwd);
    
    // Create Valkey string for logging
    ValkeyModuleString *log_str = ValkeyModule_CreateString(ctx, log_message, strlen(log_message));
    
    // Log the authentication attempt
    ValkeyModule_Log(ctx, "notice", "%s", log_message);
    
    // Add to ACL log for this user
    ValkeyModule_ACLAddLogEntryByUserName(ctx, username, log_str, VALKEYMODULE_ACL_LOG_AUTH);
    
    // Check for suspicious authentication attempts
    if (username_len > 50 || (pwd && strlen(pwd) > 100)) {
        // Set error message for potentially malicious input
        const char *err_msg = "Suspicious authentication parameters detected - logging this attempt";
        *err = ValkeyModule_CreateString(ctx, err_msg, strlen(err_msg));
        
        // Log a warning about this suspicious attempt
        ValkeyModule_Log(ctx, "warning", "Suspicious auth attempt with long parameters from user '%.*s'", 
                        (int)username_len, user);
        
        // Free the log string
        ValkeyModule_FreeString(ctx, log_str);
        
        // We'll still let the authentication flow continue, so return NOT_HANDLED
        return VALKEYMODULE_AUTH_NOT_HANDLED;
    }
    
    // Free the string we created
    ValkeyModule_FreeString(ctx, log_str);
    
    // Return NOT_HANDLED to allow the authentication process to continue normally
    return VALKEYMODULE_AUTH_NOT_HANDLED;
}

// Module initialization function
int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);
    
    // Initialize the module
    if (ValkeyModule_Init(ctx, "auth_logger", 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR)
        return VALKEYMODULE_ERR;
    
    // Register our auth logging callback
    ValkeyModule_RegisterAuthCallback(ctx, auth_logger_callback);
    
    ValkeyModule_Log(ctx, "notice", "Auth Logger module loaded successfully");
    
    return VALKEYMODULE_OK;
}