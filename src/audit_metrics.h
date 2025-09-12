// audit_metrics.h - Complete metrics header with struct definitions
#ifndef AUDIT_METRICS_H
#define AUDIT_METRICS_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "valkeymodule.h"

/**
 * @file audit_metrics.h
 * @brief Minimal audit metrics tracking for Valkey audit module
 * 
 * Provides lightweight, performance-focused metrics tracking with
 * atomic operations for hot path counters and minimal memory overhead.
 */

/**
 * Protocol status enumeration
 * 
 * Represents the current status of each audit protocol (file, syslog, TCP).
 * Used to track connection health and operational state.
 */
typedef enum {
    AUDIT_STATUS_DISCONNECTED = 0,  /**< Protocol is disconnected/not active */
    AUDIT_STATUS_CONNECTED,         /**< Protocol is connected and operational */
    AUDIT_STATUS_ERROR              /**< Protocol is in error state */
} audit_status_t;

/**
 * Main metrics structure
 * 
 * Contains all audit metrics with minimal memory footprint (~100 bytes).
 * Uses atomic counters for performance-critical operations and mutex
 * only for infrequent status updates.
 */
typedef struct {
    // Core event counters (atomic for performance)
    uint64_t total_events;      /**< Total audit events processed */
    uint64_t total_errors;      /**< Total write/send errors encountered */
    uint64_t exclusion_hits;    /**< Number of events excluded by rules */
    
    // Protocol status array (indexed by protocol type)
    // Index 0 = FILE, Index 1 = SYSLOG, Index 2 = TCP
    audit_status_t protocol_status[3];
    
    // Module lifecycle
    time_t start_time;          /**< Module initialization timestamp */
    
    // Thread safety for status updates (not needed for atomic counters)
    pthread_mutex_t lock;
    
} audit_metrics_t;

/**
 * Global metrics instance
 * 
 * Single global instance containing all audit metrics.
 * Accessible from any part of the audit module.
 */
extern audit_metrics_t g_metrics;

/**
 * Increment total event counter (hot path)
 * 
 * Uses atomic operation for maximum performance. Called for every
 * audit event, so must be as fast as possible.
 */
static inline void audit_metrics_inc_event(void) {
    __atomic_fetch_add(&g_metrics.total_events, 1, __ATOMIC_RELAXED);
}

/**
 * Increment error counter (error path)
 * 
 * Uses atomic operation. Called when write operations fail.
 */
static inline void audit_metrics_inc_error(void) {
    __atomic_fetch_add(&g_metrics.total_errors, 1, __ATOMIC_RELAXED);
}

/**
 * Increment exclusion counter (when rules match)
 * 
 * Uses atomic operation. Called when exclusion rules prevent auditing.
 */
static inline void audit_metrics_inc_exclusion(void) {
    __atomic_fetch_add(&g_metrics.exclusion_hits, 1, __ATOMIC_RELAXED);
}

/**
 * Initialize metrics system
 * 
 * Must be called during module initialization. Sets up the global
 * metrics structure and initializes synchronization primitives.
 */
void audit_metrics_init(void);

/**
 * Cleanup metrics system
 * 
 * Should be called during module unload. Cleans up synchronization
 * primitives and resets the metrics structure.
 */
void audit_metrics_destroy(void);

/**
 * Update protocol status
 * 
 * Updates the status of a specific protocol. Uses mutex since this
 * is called infrequently (only on status changes).
 * 
 * @param protocol Protocol index (0=file, 1=syslog, 2=tcp)
 * @param status New status for the protocol
 */
void audit_metrics_set_status(int protocol, audit_status_t status);

/**
 * Reset all counters
 * 
 * Resets event counters while preserving protocol status and
 * restarting the uptime timer. Used by optional reset command.
 */
void audit_metrics_reset(void);

int audit_metrics_register_info(ValkeyModuleCtx *ctx);

#define AUDIT_PROTOCOL_FILE    0
#define AUDIT_PROTOCOL_SYSLOG  1  
#define AUDIT_PROTOCOL_TCP     2

#endif // AUDIT_METRICS_H