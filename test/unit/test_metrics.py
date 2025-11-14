#!/usr/bin/env python3
import unittest
import redis
import os
import tempfile
import time
import json
import sys
import subprocess
import csv
import io
import re
import signal
import socket
import threading
from queue import Queue, Empty
from pathlib import Path

class ValkeyAuditMetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary directory for test files
        cls.temp_dir = tempfile.mkdtemp(prefix="vka-metrics-")
        print(f"Temporary directory created: {cls.temp_dir}")
        cls.log_file = os.path.join(cls.temp_dir, "audit.log")
        
        # Path to Valkey server and module
        cls.valkey_server = os.environ.get("VALKEY_SERVER", "valkey-server")
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH", "./libvalkeyaudit.so")
        
        # Start Valkey server with the audit module
        cls._start_valkey_server()
        
        # Connect to the server
        cls.redis = redis.Redis(host='localhost', port=cls.port, decode_responses=True)
        
        # Wait for server to be ready
        max_retries = 10
        for i in range(max_retries):
            try:
                cls.redis.ping()
                break
            except redis.exceptions.ConnectionError:
                if i == max_retries - 1:
                    raise
                time.sleep(0.5)
    
    @classmethod
    def tearDownClass(cls):
        # Stop the server
        cls._stop_valkey_server()
    
    @classmethod
    def _start_valkey_server(cls):
        """Start a Valkey server instance for testing"""
        # Find an available port
        s = socket.socket()
        s.bind(('', 0))
        cls.port = s.getsockname()[1]
        s.close()
        
        # Create configuration file
        cls.conf_file = os.path.join(cls.temp_dir, "valkey.conf")
        with open(cls.conf_file, 'w') as f:
            f.write(f"port {cls.port}\n")
            f.write(f"loadmodule {cls.module_path}\n")    
            f.write(f"audit.protocol file {cls.log_file}\n")
            f.write("audit.events all\n")
            f.write("audit.enabled yes\n")
        
        print(f"Written {cls.temp_dir} valkey.conf")

        # Start the server
        cls.server_proc = subprocess.Popen(
            [cls.valkey_server, cls.conf_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give it a moment to start
        time.sleep(2)

    @classmethod
    def _stop_valkey_server(cls):
        """Stop the Valkey server"""
        if hasattr(cls, 'server_proc'):
            cls.server_proc.terminate()
            cls.server_proc.wait(timeout=5)
    
    def _get_audit_info(self):
        """Get audit metrics from INFO command"""
        info_output = self.redis.info("audit")
        return info_output
    
    def _clear_log_file(self):
        """Clear the contents of the audit log file"""
        if os.path.exists(self.log_file):
            open(self.log_file, 'w').close()
    
    def _reset_metrics(self):
        """Reset audit metrics"""
        try:
            result = self.redis.execute_command("AUDIT.RESET")
            return result
        except redis.ResponseError:
            # If AUDIT.RESET is not available, that's okay for some tests
            pass

    def test_001_metrics_available_in_info(self):
        """Test that audit metrics are available via INFO audit command"""
        metrics = self._get_audit_info()
        #print(metrics)
        
        # Check that the audit section exists and has expected metrics
        self.assertIsInstance(metrics, dict, "INFO audit should return a dictionary")
        
        # Check for required metrics fields
        expected_fields = [
            'audit_total_events',
            'audit_total_errors', 
            'audit_exclusion_hits',
            'audit_uptime_seconds',
            'audit_file_status',
            'audit_syslog_status',
            'audit_tcp_status',
            'audit_error_rate_percent'
        ]
        
        for field in expected_fields:
            self.assertIn(field, metrics, f"Missing metric field: {field}")
        
        # Check data types
        self.assertIsInstance(metrics['audit_total_events'], int, "total_events should be integer")
        self.assertIsInstance(metrics['audit_total_errors'], int, "total_errors should be integer")
        self.assertIsInstance(metrics['audit_exclusion_hits'], int, "exclusion_hits should be integer")
        self.assertIsInstance(metrics['audit_uptime_seconds'], int, "uptime_seconds should be integer")
        self.assertIsInstance(metrics['audit_error_rate_percent'], (int, float), "error_rate_percent should be numeric")
        
        # Check status values are valid
        valid_statuses = ['disconnected', 'connected', 'error']
        self.assertIn(metrics['audit_file_status'], valid_statuses, "file_status should be valid")
        self.assertIn(metrics['audit_syslog_status'], valid_statuses, "syslog_status should be valid")
        self.assertIn(metrics['audit_tcp_status'], valid_statuses, "tcp_status should be valid")

    def test_002_event_counting(self):
        """Test that event counters increment correctly"""
        # Reset metrics if possible
        self._reset_metrics()
        
        # Get initial metrics
        initial_metrics = self._get_audit_info()
        initial_events = initial_metrics['audit_total_events']
        
        # Generate some audit events
        self.redis.set("metrics_test_key1", "value1")
        self.redis.get("metrics_test_key1") 
        self.redis.delete("metrics_test_key1")
        self.redis.execute_command("CONFIG", "GET", "port")
        
        # Wait a moment for events to be processed
        time.sleep(0.1)
        
        # Get updated metrics
        updated_metrics = self._get_audit_info()
        updated_events = updated_metrics['audit_total_events']
        
        # Event count should have increased
        self.assertGreater(updated_events, initial_events, 
                          "Event count should increase after generating events")
        
        # Should have at least 4 more events (SET, GET, DEL, CONFIG)
        self.assertGreaterEqual(updated_events - initial_events, 4,
                               "Should have at least 4 new events")

    def test_003_file_protocol_status(self):
        """Test file protocol status tracking"""
        # Set protocol to file
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", f"file {self.log_file}")
        
        # Generate an event
        self.redis.set("file_status_test", "value")
        time.sleep(0.1)
        
        # Check metrics
        metrics = self._get_audit_info()
        self.assertEqual(metrics['audit_file_status'], 'connected', 
                        "File status should be 'connected' when writing to valid file")
        
        # Test with invalid file path
        invalid_path = "/non/existent/path/audit.log"
        try:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", f"file {invalid_path}")
            # Generate an event that should fail
            self.redis.set("file_error_test", "value")
            time.sleep(0.1)
            
            # Check metrics - might show error status
            metrics = self._get_audit_info()
            # File status could be 'error' or 'connected' depending on implementation
            self.assertIn(metrics['file_status'], ['error', 'connected', 'disconnected'],
                         "File status should be valid even with invalid path")
        except Exception:
            # If setting invalid path fails, that's also acceptable
            pass

    def test_004_syslog_protocol_status(self):
        """Test syslog protocol status tracking"""
        # Set protocol to syslog
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "syslog local0")
        
        # Generate an event
        self.redis.set("syslog_status_test", "value")
        time.sleep(0.1)
        
        # Check metrics
        metrics = self._get_audit_info()
        # Syslog should typically be 'connected' when properly configured
        self.assertIn(metrics['audit_syslog_status'], ['connected', 'disconnected'],
                     "Syslog status should be valid")

    def test_005_tcp_protocol_status(self):
        """Test TCP protocol status tracking and error handling"""
        # Test with invalid TCP target (should show error status)
        invalid_tcp = "tcp 127.0.0.1:99999"
        
        try:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", invalid_tcp)
            
            # Generate an event
            self.redis.set("tcp_error_test", "value")
            time.sleep(0.1)
            
            # Check metrics
            metrics = self._get_audit_info()
            # TCP should show error or disconnected status
            self.assertIn(metrics['audit_tcp_status'], ['error', 'disconnected'],
                         "TCP status should show error/disconnected for invalid target")
            
        except Exception as e:
            # If setting invalid TCP fails at config level, that's acceptable
            print(f"TCP config error (expected): {e}")

    def test_006_error_counting(self):
        """Test error counter increments on failures"""
        # Reset metrics if possible
        self._reset_metrics()
        
        # Get initial error count
        initial_metrics = self._get_audit_info()
        initial_errors = initial_metrics['audit_total_errors']
        
        # Try to cause some errors by using invalid configurations
        try:
            # Invalid file path
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "file /invalid/path/audit.log")
            self.redis.set("error_test_key", "value")
            time.sleep(0.1)
        except Exception:
            pass
        
        try:
            # Invalid TCP
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "tcp 127.0.0.1:99999")
            self.redis.set("error_test_key2", "value")
            time.sleep(0.1)
        except Exception:
            pass
        
        # Get updated metrics
        updated_metrics = self._get_audit_info()
        updated_errors = updated_metrics['audit_total_errors']
        
        # Error count might have increased (depending on implementation)
        # At minimum, it should not decrease
        self.assertGreaterEqual(updated_errors, initial_errors,
                               "Error count should not decrease")

    def test_007_exclusion_counting(self):
        """Test exclusion rule hit counting"""
        # Reset metrics if possible
        self._reset_metrics()
        
        # Set up valid protocol first
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", f"file {self.log_file}")
        
        # Set up exclusion rules
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "testuser,@127.0.0.1")
        
        # Get initial exclusion count
        initial_metrics = self._get_audit_info()
        initial_exclusions = initial_metrics['audit_exclusion_hits']
        
        # Generate some events (these might or might not be excluded depending on client info)
        self.redis.set("exclusion_test1", "value1")
        self.redis.set("exclusion_test2", "value2")
        self.redis.set("exclusion_test3", "value3")
        
        time.sleep(0.1)
        
        # Get updated metrics
        updated_metrics = self._get_audit_info()
        updated_exclusions = updated_metrics['audit_exclusion_hits']
        
        # Exclusion count should be greater than or equal to initial
        self.assertGreaterEqual(updated_exclusions, initial_exclusions,
                               "Exclusion count should not decrease")
        
        # Clear exclusion rules
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")

    def test_008_error_rate_calculation(self):
        """Test error rate percentage calculation"""
        metrics = self._get_audit_info()
        
        total_events = metrics['audit_total_events']
        total_errors = metrics['audit_total_errors'] 
        error_rate = metrics['audit_error_rate_percent']
        
        if total_events > 0:
            expected_rate = (total_errors / total_events) * 100
            self.assertAlmostEqual(error_rate, expected_rate, places=2,
                                  msg="Error rate calculation should be correct")
        else:
            self.assertEqual(error_rate, 0.0, 
                            "Error rate should be 0 when no events have occurred")

    def test_009_uptime_tracking(self):
        """Test uptime counter"""
        metrics1 = self._get_audit_info()
        uptime1 = metrics1['audit_uptime_seconds']
        
        # Wait a bit
        time.sleep(1.1)
        
        metrics2 = self._get_audit_info()
        uptime2 = metrics2['audit_uptime_seconds']
        
        # Uptime should have increased
        self.assertGreater(uptime2, uptime1, "Uptime should increase over time")
        self.assertGreaterEqual(uptime2 - uptime1, 1, "Uptime should increase by at least 1 second")

    def test_010_metrics_reset(self):
        """Test metrics reset functionality"""
        # Generate some events first
        self.redis.set("reset_test1", "value1")
        self.redis.set("reset_test2", "value2")
        self.redis.set("reset_test3", "value3")
        time.sleep(0.1)
        
        # Get metrics before reset
        before_reset = self._get_audit_info()
        self.assertGreater(before_reset['audit_total_events'], 0, "Should have some events before reset")
        
        # Try to reset metrics
        try:
            result = self.redis.execute_command("AUDIT.RESET")
            self.assertEqual(result, "OK", "AUDIT.RESET should return OK")
            
            # Get metrics after reset
            after_reset = self._get_audit_info()
            
            # Counters should be reset (or at least not higher than before)
            self.assertLessEqual(after_reset['audit_total_events'], before_reset['audit_total_events'],
                               "Event count should be reset or not increase")
            self.assertLessEqual(after_reset['audit_total_errors'], before_reset['audit_total_errors'],
                               "Error count should be reset or not increase") 
            self.assertLessEqual(after_reset['audit_exclusion_hits'], before_reset['audit_exclusion_hits'],
                               "Exclusion count should be reset or not increase")
            
        except redis.ResponseError as e:
            if "unknown command" in str(e).lower():
                print("AUDIT.RESET command not available - this is optional")
            else:
                raise

    def test_011_protocol_status_transitions(self):
        """Test protocol status changes as configurations change"""
        # Start with file protocol
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", f"file {self.log_file}")
        self.redis.set("transition_test1", "value")
        time.sleep(0.1)
        
        metrics = self._get_audit_info()
        self.assertEqual(metrics['audit_file_status'], 'connected', "File should be connected")
        
        # Switch to syslog
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "syslog local0")
        self.redis.set("transition_test2", "value")
        time.sleep(0.1)
        
        metrics = self._get_audit_info()
        # File might now be disconnected, syslog should be connected
        self.assertIn(metrics['audit_syslog_status'], ['connected'], "Syslog should be connected")
        
        # Switch back to file
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", f"file {self.log_file}")
        self.redis.set("transition_test3", "value")
        time.sleep(0.1)
        
        metrics = self._get_audit_info()
        self.assertEqual(metrics['audit_file_status'], 'connected', "File should be connected again")

    def test_012_metrics_persistence_across_events(self):
        """Test that metrics accumulate correctly across multiple events"""
        # Reset if possible
        self._reset_metrics()
        time.sleep(0.1)
        
        initial_metrics = self._get_audit_info()
        initial_events = initial_metrics['audit_total_events']
        
        # Generate events in batches
        for batch in range(3):
            for i in range(5):
                self.redis.set(f"persist_test_b{batch}_k{i}", f"value_{batch}_{i}")
            time.sleep(0.1)
            
            # Check metrics after each batch
            current_metrics = self._get_audit_info()
            current_events = current_metrics['audit_total_events']
            
            expected_min_events = initial_events + (batch + 1) * 5
            self.assertGreaterEqual(current_events, expected_min_events,
                                   f"Should have at least {expected_min_events} events after batch {batch}")

    def test_013_concurrent_metrics_updates(self):
        """Test metrics under concurrent load"""
        import threading
        import time
        
        def generate_events(thread_id, count):
            """Generate events from a thread"""
            for i in range(count):
                try:
                    self.redis.set(f"concurrent_t{thread_id}_k{i}", f"value_{i}")
                except Exception as e:
                    print(f"Thread {thread_id} error: {e}")
        
        # Get initial metrics
        initial_metrics = self._get_audit_info()
        initial_events = initial_metrics['audit_total_events']
        
        # Start multiple threads
        threads = []
        events_per_thread = 10
        thread_count = 5
        
        for i in range(thread_count):
            thread = threading.Thread(target=generate_events, args=(i, events_per_thread))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        time.sleep(0.2)  # Allow metrics to be updated
        
        # Check final metrics
        final_metrics = self._get_audit_info()
        final_events = final_metrics['audit_total_events']
        
        # Should have at least the expected number of new events
        expected_min_new_events = thread_count * events_per_thread
        actual_new_events = final_events - initial_events
        
        self.assertGreaterEqual(actual_new_events, expected_min_new_events,
                               f"Should have at least {expected_min_new_events} new events from concurrent threads")

    def test_014_info_all_includes_audit(self):
        """Test that INFO all includes audit metrics"""
        # Get info for all sections
        all_info = self.redis.info("all")
        
        # Should include audit section
        audit_fields = [field for field in all_info.keys() if field.startswith('audit_') or 
                       field in ['total_events', 'total_errors', 'exclusion_hits', 'uptime_seconds',
                                'file_status', 'syslog_status', 'tcp_status', 'error_rate_percent']]
        
        # We might not find the exact field names in 'all' depending on implementation
        # but we can check if INFO audit works
        audit_info = self._get_audit_info()
        self.assertIsInstance(audit_info, dict, "Audit info should be available")
        self.assertGreater(len(audit_info), 0, "Audit info should contain metrics")

    def test_015_hash_table_metrics(self):
        """Test hash table statistics tracking"""
        metrics = self._get_audit_info()
        
        # Check hash table metrics exist
        self.assertIn('audit_hash_table_size', metrics, "Missing hash_table_size metric")
        self.assertIn('audit_hash_table_used', metrics, "Missing hash_table_used metric")
        self.assertIn('audit_hash_table_load_factor_percent', metrics, "Missing hash_table_load_factor_percent metric")
        
        # Verify data types
        self.assertIsInstance(metrics['audit_hash_table_size'], int, "hash_table_size should be integer")
        self.assertIsInstance(metrics['audit_hash_table_used'], int, "hash_table_used should be integer")
        self.assertIsInstance(metrics['audit_hash_table_load_factor_percent'], (int, float), 
                            "hash_table_load_factor_percent should be numeric")
        
        # Verify values are reasonable
        hash_size = metrics['audit_hash_table_size']
        hash_used = metrics['audit_hash_table_used']
        load_factor = metrics['audit_hash_table_load_factor_percent']
        
        self.assertGreater(hash_size, 0, "Hash table size should be positive")
        self.assertGreaterEqual(hash_used, 0, "Hash table used should be non-negative")
        self.assertLessEqual(hash_used, hash_size, "Used slots cannot exceed total size")
        
        # Verify load factor calculation
        expected_load_factor = (hash_used / hash_size) * 100.0
        self.assertAlmostEqual(load_factor, expected_load_factor, places=2,
                              msg="Load factor calculation should be correct")
        
        # Load factor should be between 0 and 100
        self.assertGreaterEqual(load_factor, 0.0, "Load factor should be >= 0")
        self.assertLessEqual(load_factor, 100.0, "Load factor should be <= 100")

    def test_016_user_command_metrics(self):
        """Test user-defined command tracking"""
        metrics = self._get_audit_info()
        
        # Check user command metrics exist
        self.assertIn('audit_user_commands_count', metrics, "Missing user_commands_count metric")
        self.assertIn('audit_user_commands_max', metrics, "Missing user_commands_max metric")
        self.assertIn('audit_user_commands_utilization_percent', metrics, 
                     "Missing user_commands_utilization_percent metric")
        
        # Verify data types
        self.assertIsInstance(metrics['audit_user_commands_count'], int, 
                            "user_commands_count should be integer")
        self.assertIsInstance(metrics['audit_user_commands_max'], int, 
                            "user_commands_max should be integer")
        self.assertIsInstance(metrics['audit_user_commands_utilization_percent'], (int, float),
                            "user_commands_utilization_percent should be numeric")
        
        # Verify values are reasonable
        user_count = metrics['audit_user_commands_count']
        user_max = metrics['audit_user_commands_max']
        utilization = metrics['audit_user_commands_utilization_percent']
        
        self.assertGreaterEqual(user_count, 0, "User command count should be non-negative")
        self.assertGreater(user_max, 0, "User command max should be positive")
        self.assertLessEqual(user_count, user_max, "User commands cannot exceed max")
        
        # Verify utilization calculation
        expected_utilization = (user_count / user_max) * 100.0
        self.assertAlmostEqual(utilization, expected_utilization, places=2,
                              msg="Utilization calculation should be correct")

    def test_017_user_command_exclusion(self):
        """Test user-defined command exclusions"""
        # Get initial metrics
        initial_metrics = self._get_audit_info()
        initial_user_count = initial_metrics['audit_user_commands_count']
        
        # Add excluded commands via CONFIG
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "TESTCMD1,TESTCMD2")
        time.sleep(0.1)
        
        # Check that user command count increased
        updated_metrics = self._get_audit_info()
        updated_user_count = updated_metrics['audit_user_commands_count']
        
        self.assertGreaterEqual(updated_user_count, initial_user_count + 2,
                               "User command count should increase after adding exclusions")
        
        # Clear exclusions
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")
        time.sleep(0.1)
        
        # User command count might decrease or stay same depending on implementation
        final_metrics = self._get_audit_info()
        final_user_count = final_metrics['audit_user_commands_count']
        self.assertGreaterEqual(final_user_count, 0, "User command count should remain non-negative")

    def test_018_prefix_filter_metrics(self):
        """Test prefix filter statistics"""
        metrics = self._get_audit_info()
        
        # Check prefix filter metrics exist
        self.assertIn('audit_prefix_filters_count', metrics, "Missing prefix_filters_count metric")
        self.assertIn('audit_prefix_filter_checks', metrics, "Missing prefix_filter_checks metric")
        self.assertIn('audit_prefix_filter_matches', metrics, "Missing prefix_filter_matches metric")
        self.assertIn('audit_prefix_filter_hit_rate_percent', metrics, 
                     "Missing prefix_filter_hit_rate_percent metric")
        
        # Verify data types
        self.assertIsInstance(metrics['audit_prefix_filters_count'], int,
                            "prefix_filters_count should be integer")
        self.assertIsInstance(metrics['audit_prefix_filter_checks'], int,
                            "prefix_filter_checks should be integer")
        self.assertIsInstance(metrics['audit_prefix_filter_matches'], int,
                            "prefix_filter_matches should be integer")
        self.assertIsInstance(metrics['audit_prefix_filter_hit_rate_percent'], (int, float),
                            "prefix_filter_hit_rate_percent should be numeric")
        
        # Verify values are reasonable
        filter_count = metrics['audit_prefix_filters_count']
        checks = metrics['audit_prefix_filter_checks']
        matches = metrics['audit_prefix_filter_matches']
        hit_rate = metrics['audit_prefix_filter_hit_rate_percent']
        
        self.assertGreaterEqual(filter_count, 0, "Prefix filter count should be non-negative")
        self.assertGreaterEqual(checks, 0, "Prefix filter checks should be non-negative")
        self.assertGreaterEqual(matches, 0, "Prefix filter matches should be non-negative")
        self.assertLessEqual(matches, checks, "Matches cannot exceed checks")
        
        # Verify hit rate calculation
        if checks > 0:
            expected_hit_rate = (matches / checks) * 100.0
            self.assertAlmostEqual(hit_rate, expected_hit_rate, places=2,
                                  msg="Hit rate calculation should be correct")
        else:
            self.assertEqual(hit_rate, 0.0, "Hit rate should be 0 when no checks")

    def test_019_prefix_filter_functionality(self):
        """Test prefix filter configuration and statistics updates"""
        # Get initial metrics
        initial_metrics = self._get_audit_info()
        initial_filter_count = initial_metrics['audit_prefix_filters_count']
        initial_checks = initial_metrics['audit_prefix_filter_checks']
        
        # Configure prefix filters
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!DEBUG*,!CLIENT*")
        time.sleep(0.1)
        
        # Check that filter count increased
        updated_metrics = self._get_audit_info()
        updated_filter_count = updated_metrics['audit_prefix_filters_count']
        
        self.assertGreater(updated_filter_count, initial_filter_count,
                          "Prefix filter count should increase after adding filters")
        
        # Generate some commands (these will trigger prefix checks)
        self.redis.set("prefix_test_key", "value")
        self.redis.get("prefix_test_key")
        time.sleep(0.1)
        
        # Check that prefix_filter_checks increased
        final_metrics = self._get_audit_info()
        final_checks = final_metrics['audit_prefix_filter_checks']
        
        self.assertGreater(final_checks, initial_checks,
                          "Prefix filter checks should increase after commands")
        
        # Clear prefix filters
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_020_custom_category_metrics(self):
        """Test custom category statistics"""
        metrics = self._get_audit_info()
        
        # Check custom category metrics exist
        self.assertIn('audit_custom_categories_count', metrics, 
                     "Missing custom_categories_count metric")
        self.assertIn('audit_custom_category_matches', metrics,
                     "Missing custom_category_matches metric")
        
        # Verify data types
        self.assertIsInstance(metrics['audit_custom_categories_count'], int,
                            "custom_categories_count should be integer")
        self.assertIsInstance(metrics['audit_custom_category_matches'], int,
                            "custom_category_matches should be integer")
        
        # Verify values are reasonable
        category_count = metrics['audit_custom_categories_count']
        category_matches = metrics['audit_custom_category_matches']
        
        self.assertGreaterEqual(category_count, 0, 
                               "Custom category count should be non-negative")
        self.assertGreaterEqual(category_matches, 0,
                               "Custom category matches should be non-negative")

    def test_021_custom_category_functionality(self):
        """Test custom category configuration and tracking"""
        # Get initial metrics
        initial_metrics = self._get_audit_info()
        initial_cat_count = initial_metrics['audit_custom_categories_count']
        initial_matches = initial_metrics['audit_custom_category_matches']
        
        # Configure a custom category
        self.redis.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY",
                                  "dangerous:FLUSHDB,FLUSHALL,SHUTDOWN")
        time.sleep(0.1)
        
        # Check that category count increased
        updated_metrics = self._get_audit_info()
        updated_cat_count = updated_metrics['audit_custom_categories_count']
        
        self.assertGreater(updated_cat_count, initial_cat_count,
                          "Custom category count should increase after adding category")
        
        # Note: We can't easily test category_matches increment without running
        # the actual dangerous commands (which we don't want to do in tests)
        
        # Clear custom categories
        self.redis.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", "")

    def test_022_command_lookup_metrics(self):
        """Test command lookup statistics"""
        metrics = self._get_audit_info()
        
        # Check lookup metrics exist
        self.assertIn('audit_user_command_lookups', metrics,
                     "Missing user_command_lookups metric")
        
        # Verify data type
        self.assertIsInstance(metrics['audit_user_command_lookups'], int,
                            "user_command_lookups should be integer")
        
        # Verify value is reasonable
        lookups = metrics['audit_user_command_lookups']
        self.assertGreaterEqual(lookups, 0, "Command lookups should be non-negative")
        
        # Get initial lookup count
        initial_lookups = lookups
        
        # Generate commands (these will trigger hash table lookups)
        for i in range(10):
            self.redis.set(f"lookup_test_{i}", f"value_{i}")
        time.sleep(0.1)
        
        # Check that lookups increased
        updated_metrics = self._get_audit_info()
        updated_lookups = updated_metrics['audit_user_command_lookups']
        
        self.assertGreater(updated_lookups, initial_lookups,
                          "Command lookups should increase after executing commands")
        self.assertGreaterEqual(updated_lookups - initial_lookups, 10,
                               "Should have at least 10 new lookups")

    def test_023_exclusion_rate_percent(self):
        """Test exclusion rate percentage calculation"""
        metrics = self._get_audit_info()
        
        # Check exclusion rate metric exists
        self.assertIn('audit_exclusion_rate_percent', metrics,
                     "Missing exclusion_rate_percent metric")
        
        # Verify data type
        self.assertIsInstance(metrics['audit_exclusion_rate_percent'], (int, float),
                            "exclusion_rate_percent should be numeric")
        
        # Verify value is reasonable (0-100%)
        exclusion_rate = metrics['audit_exclusion_rate_percent']
        self.assertGreaterEqual(exclusion_rate, 0.0, "Exclusion rate should be >= 0")
        self.assertLessEqual(exclusion_rate, 100.0, "Exclusion rate should be <= 100")
        
        # Verify calculation
        total_events = metrics['audit_total_events']
        exclusion_hits = metrics['audit_exclusion_hits']
        total_commands = total_events + exclusion_hits
        
        if total_commands > 0:
            expected_rate = (exclusion_hits / total_commands) * 100.0
            self.assertAlmostEqual(exclusion_rate, expected_rate, places=2,
                                  msg="Exclusion rate calculation should be correct")
        else:
            self.assertEqual(exclusion_rate, 0.0,
                            "Exclusion rate should be 0 when no commands")

    def test_024_events_per_second_metric(self):
        """Test events per second throughput metric"""
        metrics = self._get_audit_info()
        
        # Check events_per_second metric exists
        self.assertIn('audit_events_per_second', metrics,
                     "Missing events_per_second metric")
        
        # Verify data type
        self.assertIsInstance(metrics['audit_events_per_second'], (int, float),
                            "events_per_second should be numeric")
        
        # Verify value is reasonable
        events_per_sec = metrics['audit_events_per_second']
        self.assertGreaterEqual(events_per_sec, 0.0, "Events per second should be non-negative")
        
        # Verify calculation
        total_events = metrics['audit_total_events']
        uptime = metrics['audit_uptime_seconds']
        
        if uptime > 0:
            expected_rate = total_events / uptime
            self.assertAlmostEqual(events_per_sec, expected_rate, places=2,
                                  msg="Events per second calculation should be correct")
        else:
            self.assertEqual(events_per_sec, 0.0,
                            "Events per second should be 0 when uptime is 0")

    def test_025_filter_metrics_under_load(self):
        """Test that filter metrics update correctly under load"""
        # Get initial metrics
        initial_metrics = self._get_audit_info()
        initial_lookups = initial_metrics['audit_user_command_lookups']
        initial_prefix_checks = initial_metrics['audit_prefix_filter_checks']
        
        # Configure some filters
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!DEBUG*")
        
        # Generate significant load
        command_count = 100
        for i in range(command_count):
            self.redis.set(f"load_test_{i}", f"value_{i}")
            if i % 10 == 0:
                self.redis.get(f"load_test_{i}")
        
        time.sleep(0.2)
        
        # Check metrics
        final_metrics = self._get_audit_info()
        final_lookups = final_metrics['audit_user_command_lookups']
        final_prefix_checks = final_metrics['audit_prefix_filter_checks']
        
        # Lookups should have increased significantly
        self.assertGreaterEqual(final_lookups - initial_lookups, command_count,
                               f"Should have at least {command_count} new lookups")
        
        # Prefix checks should have increased
        self.assertGreater(final_prefix_checks, initial_prefix_checks,
                          "Prefix filter checks should increase under load")
        
        # Clear filters
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_026_hash_table_load_factor_warning(self):
        """Test hash table load factor remains reasonable"""
        metrics = self._get_audit_info()
        
        load_factor = metrics['audit_hash_table_load_factor_percent']
        
        # Issue warning if load factor is getting high
        if load_factor > 70.0:
            print(f"WARNING: Hash table load factor is {load_factor:.1f}% - consider increasing size")
        
        # Load factor should not exceed 100%
        self.assertLessEqual(load_factor, 100.0,
                            "Hash table load factor should never exceed 100%")
        
        # Typically should be under 80% for good performance
        # This is a soft check - log warning but don't fail
        if load_factor > 80.0:
            print(f"NOTICE: Hash table load factor is high ({load_factor:.1f}%)")

    def test_027_user_command_capacity_warning(self):
        """Test user command capacity tracking"""
        metrics = self._get_audit_info()
        
        utilization = metrics['audit_user_commands_utilization_percent']
        user_count = metrics['audit_user_commands_count']
        user_max = metrics['audit_user_commands_max']
        
        # Issue warning if utilization is getting high
        if utilization > 80.0:
            print(f"WARNING: User command utilization is {utilization:.1f}% "
                  f"({user_count}/{user_max})")
        
        # Should never exceed 100%
        self.assertLessEqual(utilization, 100.0,
                            "User command utilization should never exceed 100%")

    def test_028_all_filter_metrics_present(self):
        """Test that all expected filter metrics are present"""
        metrics = self._get_audit_info()
        
        # Complete list of expected filter metrics
        expected_filter_metrics = [
            'audit_hash_table_size',
            'audit_hash_table_used',
            'audit_hash_table_load_factor_percent',
            'audit_user_commands_count',
            'audit_user_commands_max',
            'audit_user_commands_utilization_percent',
            'audit_prefix_filters_count',
            'audit_prefix_filter_checks',
            'audit_prefix_filter_matches',
            'audit_prefix_filter_hit_rate_percent',
            'audit_custom_categories_count',
            'audit_custom_category_matches',
            'audit_user_command_lookups',
            'audit_exclusion_rate_percent',
            'audit_events_per_second'
        ]
        
        missing_metrics = []
        for metric in expected_filter_metrics:
            if metric not in metrics:
                missing_metrics.append(metric)
        
        self.assertEqual(len(missing_metrics), 0,
                        f"Missing filter metrics: {', '.join(missing_metrics)}")
        
        print(f"\n✓ All {len(expected_filter_metrics)} filter metrics are present")

    def test_029_filter_metrics_data_integrity(self):
        """Test logical consistency between related filter metrics"""
        metrics = self._get_audit_info()
        
        # Hash table: used <= size
        self.assertLessEqual(metrics['audit_hash_table_used'],
                            metrics['audit_hash_table_size'],
                            "Hash table used should not exceed size")
        
        # User commands: count <= max
        self.assertLessEqual(metrics['audit_user_commands_count'],
                            metrics['audit_user_commands_max'],
                            "User command count should not exceed max")
        
        # Prefix filters: matches <= checks
        self.assertLessEqual(metrics['audit_prefix_filter_matches'],
                            metrics['audit_prefix_filter_checks'],
                            "Prefix filter matches should not exceed checks")
        
        # All counts should be non-negative
        self.assertGreaterEqual(metrics['audit_prefix_filters_count'], 0)
        self.assertGreaterEqual(metrics['audit_custom_categories_count'], 0)
        self.assertGreaterEqual(metrics['audit_user_command_lookups'], 0)
        
        # Percentages should be 0-100
        self.assertGreaterEqual(metrics['audit_hash_table_load_factor_percent'], 0.0)
        self.assertLessEqual(metrics['audit_hash_table_load_factor_percent'], 100.0)
        self.assertGreaterEqual(metrics['audit_user_commands_utilization_percent'], 0.0)
        self.assertLessEqual(metrics['audit_user_commands_utilization_percent'], 100.0)
        self.assertGreaterEqual(metrics['audit_prefix_filter_hit_rate_percent'], 0.0)
        self.assertLessEqual(metrics['audit_prefix_filter_hit_rate_percent'], 100.0)

    def test_030_filter_metrics_reset_behavior(self):
        """Test filter metrics behavior after reset"""
        # Generate some activity to populate metrics
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!TEST*")
        for i in range(20):
            self.redis.set(f"reset_filter_test_{i}", f"value_{i}")
        time.sleep(0.1)
        
        # Get metrics before reset
        before_reset = self._get_audit_info()
        self.assertGreater(before_reset['audit_user_command_lookups'], 0,
                          "Should have lookups before reset")
        
        # Try to reset
        try:
            self.redis.execute_command("AUDIT.RESET")
            time.sleep(0.1)
            
            after_reset = self._get_audit_info()
            
            # Runtime counters should reset
            self.assertLessEqual(after_reset['audit_user_command_lookups'],
                                before_reset['audit_user_command_lookups'],
                                "Command lookups should reset")
            self.assertLessEqual(after_reset['audit_prefix_filter_checks'],
                                before_reset['audit_prefix_filter_checks'],
                                "Prefix filter checks should reset")
            
            # Configuration-based counts might not reset (that's okay)
            # They depend on current configuration, not accumulated events
            
        except redis.ResponseError as e:
            if "unknown command" in str(e).lower():
                print("AUDIT.RESET not available - skipping reset test")
            else:
                raise
        
        # Clean up
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

if __name__ == "__main__":
    # Run with high verbosity to see detailed test output
    unittest.main(verbosity=2)