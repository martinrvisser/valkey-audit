// audit_metrics.c - Complete metrics implementation with INFO integration
#include "common.h"
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
    
    // preserve protocol_status values as they are current operational state
    
    pthread_mutex_unlock(&g_metrics.lock);
}

/**
 * INFO callback function for audit metrics
 */
void AuditInfoFunc(ValkeyModuleInfoCtx *ctx, int for_crash_report) {
    VALKEYMODULE_NOT_USED(for_crash_report);
    
    // Get BOTH types of statistics
    AuditFilterStats filter_stats = getAuditFilterStats();        // Snapshot stats
    AuditRuntimeStats runtime_stats = getAuditRuntimeStats();     // Runtime counters
    
    ValkeyModule_InfoAddSection(ctx, "audit");
    
    // === Basic Event Metrics ===
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
    
    // === Protocol Status ===
    pthread_mutex_lock(&g_metrics.lock);
    
    const char* status_names[] = {"disconnected", "connected", "error"};
    
    ValkeyModule_InfoAddFieldCString(ctx, "file_status", 
                                     status_names[g_metrics.protocol_status[AUDIT_PROTOCOL_FILE]]);
    ValkeyModule_InfoAddFieldCString(ctx, "syslog_status", 
                                     status_names[g_metrics.protocol_status[AUDIT_PROTOCOL_SYSLOG]]);
    ValkeyModule_InfoAddFieldCString(ctx, "tcp_status", 
                                     status_names[g_metrics.protocol_status[AUDIT_PROTOCOL_TCP]]);
    
    pthread_mutex_unlock(&g_metrics.lock);
    
    // === Error Rate ===
    uint64_t total_events_snapshot = __atomic_load_n(&g_metrics.total_events, __ATOMIC_RELAXED);
    uint64_t total_errors_snapshot = __atomic_load_n(&g_metrics.total_errors, __ATOMIC_RELAXED);
    
    if (total_events_snapshot > 0) {
        double error_rate = (double)total_errors_snapshot / total_events_snapshot * 100.0;
        ValkeyModule_InfoAddFieldDouble(ctx, "error_rate_percent", error_rate);
    } else {
        ValkeyModule_InfoAddFieldDouble(ctx, "error_rate_percent", 0.0);
    }
    
    // === Hash Table Statistics (from snapshot) ===
    ValkeyModule_InfoAddFieldLongLong(ctx, "hash_table_size", filter_stats.hash_table_size);
    ValkeyModule_InfoAddFieldLongLong(ctx, "hash_table_used", filter_stats.hash_table_used);
    
    double load_factor = (double)filter_stats.hash_table_used / filter_stats.hash_table_size * 100.0;
    ValkeyModule_InfoAddFieldDouble(ctx, "hash_table_load_factor_percent", load_factor);
    
    // === User Command Statistics (from snapshot) ===
    ValkeyModule_InfoAddFieldLongLong(ctx, "user_commands_count", filter_stats.user_commands_count);
    ValkeyModule_InfoAddFieldLongLong(ctx, "user_commands_max", filter_stats.user_commands_max);
    
    double user_cmd_utilization = (double)filter_stats.user_commands_count / filter_stats.user_commands_max * 100.0;
    ValkeyModule_InfoAddFieldDouble(ctx, "user_commands_utilization_percent", user_cmd_utilization);
    
    // === Prefix Filter Statistics (MIXED: count from snapshot, checks/matches from runtime) ===
    ValkeyModule_InfoAddFieldLongLong(ctx, "prefix_filters_count", filter_stats.prefix_filters_count);
    ValkeyModule_InfoAddFieldULongLong(ctx, "prefix_filter_checks", runtime_stats.prefix_filter_checks);
    ValkeyModule_InfoAddFieldULongLong(ctx, "prefix_filter_matches", runtime_stats.prefix_filter_matches);
    
    if (runtime_stats.prefix_filter_checks > 0) {
        double prefix_hit_rate = (double)runtime_stats.prefix_filter_matches / 
                                 runtime_stats.prefix_filter_checks * 100.0;
        ValkeyModule_InfoAddFieldDouble(ctx, "prefix_filter_hit_rate_percent", prefix_hit_rate);
    } else {
        ValkeyModule_InfoAddFieldDouble(ctx, "prefix_filter_hit_rate_percent", 0.0);
    }
    
    // === Custom Category Statistics (MIXED) ===
    ValkeyModule_InfoAddFieldLongLong(ctx, "custom_categories_count", filter_stats.custom_categories_count);
    ValkeyModule_InfoAddFieldULongLong(ctx, "custom_category_matches", runtime_stats.custom_category_matches);
    
    // === Command Lookup Statistics (from runtime) ===
    ValkeyModule_InfoAddFieldULongLong(ctx, "user_command_lookups", runtime_stats.user_command_lookups);
    
    // === Exclusion Rate ===
    uint64_t exclusion_hits_snapshot = __atomic_load_n(&g_metrics.exclusion_hits, __ATOMIC_RELAXED);
    uint64_t total_commands = total_events_snapshot + exclusion_hits_snapshot;
    
    if (total_commands > 0) {
        double exclusion_rate = (double)exclusion_hits_snapshot / total_commands * 100.0;
        ValkeyModule_InfoAddFieldDouble(ctx, "exclusion_rate_percent", exclusion_rate);
    } else {
        ValkeyModule_InfoAddFieldDouble(ctx, "exclusion_rate_percent", 0.0);
    }
    
    // === Performance Metrics ===
    if (uptime > 0) {
        double events_per_second = (double)total_events_snapshot / uptime;
        ValkeyModule_InfoAddFieldDouble(ctx, "events_per_second", events_per_second);
    } else {
        ValkeyModule_InfoAddFieldDouble(ctx, "events_per_second", 0.0);
    }
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
    VALKEYMODULE_NOT_USED(argc);
  
    // Reset the metrics
    audit_metrics_reset();
    
    // Return success
    ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    return VALKEYMODULE_OK;
}