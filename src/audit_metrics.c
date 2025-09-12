// audit_metrics.c - Complete metrics implementation with INFO integration
#include "audit_metrics.h"
#include "valkeymodule.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>

// Global metrics instance definition
audit_metrics_t g_metrics;

/**
 * Initialize the metrics system
 */
void audit_metrics_init(void) {
    // Zero out the entire structure
    memset(&g_metrics, 0, sizeof(audit_metrics_t));
    
    // Set initial timestamp
    g_metrics.start_time = time(NULL);
    
    // Initialize all protocol statuses as disconnected
    for (int i = 0; i < 3; i++) {
        g_metrics.protocol_status[i] = AUDIT_STATUS_DISCONNECTED;
    }
    
    // Initialize mutex for status updates
    pthread_mutex_init(&g_metrics.lock, NULL);
}

/**
 * Cleanup the metrics system
 */
void audit_metrics_destroy(void) {
    // Destroy the mutex
    pthread_mutex_destroy(&g_metrics.lock);
    
    // Zero out the structure for safety
    memset(&g_metrics, 0, sizeof(audit_metrics_t));
}

/**
 * Update protocol status
 */
void audit_metrics_set_status(int protocol, audit_status_t status) {
    // Validate protocol index
    if (protocol < 0 || protocol >= 3) {
        return;
    }
    
    // Update status under mutex protection
    pthread_mutex_lock(&g_metrics.lock);
    g_metrics.protocol_status[protocol] = status;
    pthread_mutex_unlock(&g_metrics.lock);
}

/**
 * Reset all metric counters
 */
void audit_metrics_reset(void) {
    pthread_mutex_lock(&g_metrics.lock);
    
    // Reset atomic counters (safe to do under mutex)
    g_metrics.total_events = 0;
    g_metrics.total_errors = 0;
    g_metrics.exclusion_hits = 0;
    
    // Reset start time for uptime calculation
    g_metrics.start_time = time(NULL);
    
    // Note: We intentionally preserve protocol_status values
    // as they represent current operational state, not counters
    
    pthread_mutex_unlock(&g_metrics.lock);
}

/**
 * INFO callback function for audit metrics
 */
void AuditInfoFunc(ValkeyModuleInfoCtx *ctx, int for_crash_report) {
    VALKEYMODULE_NOT_USED(for_crash_report);
    
    // Add the audit section header
    ValkeyModule_InfoAddSection(ctx, "audit");
    
    // Add atomic counters (safe to read without mutex)
    ValkeyModule_InfoAddFieldULongLong(ctx, "total_events", 
                                       __atomic_load_n(&g_metrics.total_events, __ATOMIC_RELAXED));
    ValkeyModule_InfoAddFieldULongLong(ctx, "total_errors", 
                                       __atomic_load_n(&g_metrics.total_errors, __ATOMIC_RELAXED));
    ValkeyModule_InfoAddFieldULongLong(ctx, "exclusion_hits", 
                                       __atomic_load_n(&g_metrics.exclusion_hits, __ATOMIC_RELAXED));
    
    // Calculate and add uptime
    time_t current_time = time(NULL);
    time_t uptime = current_time - g_metrics.start_time;
    ValkeyModule_InfoAddFieldLongLong(ctx, "uptime_seconds", uptime);
    
    // Add protocol status (need mutex for consistent snapshot)
    pthread_mutex_lock(&g_metrics.lock);
    
    const char* status_names[] = {"disconnected", "connected", "error"};
    
    // Add individual protocol statuses
    ValkeyModule_InfoAddFieldCString(ctx, "file_status", 
                                     status_names[g_metrics.protocol_status[AUDIT_PROTOCOL_FILE]]);
    ValkeyModule_InfoAddFieldCString(ctx, "syslog_status", 
                                     status_names[g_metrics.protocol_status[AUDIT_PROTOCOL_SYSLOG]]);
    ValkeyModule_InfoAddFieldCString(ctx, "tcp_status", 
                                     status_names[g_metrics.protocol_status[AUDIT_PROTOCOL_TCP]]);
    
    // Calculate and add error rate if we have events
    uint64_t total_events_snapshot = __atomic_load_n(&g_metrics.total_events, __ATOMIC_RELAXED);
    uint64_t total_errors_snapshot = __atomic_load_n(&g_metrics.total_errors, __ATOMIC_RELAXED);
    
    if (total_events_snapshot > 0) {
        double error_rate = (double)total_errors_snapshot / total_events_snapshot * 100.0;
        ValkeyModule_InfoAddFieldDouble(ctx, "error_rate_percent", error_rate);
    } else {
        ValkeyModule_InfoAddFieldDouble(ctx, "error_rate_percent", 0.0);
    }
    
    pthread_mutex_unlock(&g_metrics.lock);
}

/**
 * Register audit metrics with Valkey's INFO system
 */
int audit_metrics_register_info(ValkeyModuleCtx *ctx) {
    if (ValkeyModule_RegisterInfoFunc(ctx, AuditInfoFunc) == VALKEYMODULE_ERR) {
        return VALKEYMODULE_ERR;
    }
    return VALKEYMODULE_OK;
}

/**
 * Optional stats reset command implementation
 */
int AuditStatsResetCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    
    // Validate argument count
    if (argc != 1) {
        return ValkeyModule_WrongArity(ctx);
    }
    
    // Reset the metrics
    audit_metrics_reset();
    
    // Return success
    ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    return VALKEYMODULE_OK;
}