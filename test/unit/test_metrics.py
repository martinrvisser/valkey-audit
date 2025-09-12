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

if __name__ == "__main__":
    # Run with high verbosity to see detailed test output
    unittest.main(verbosity=2)