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
import inspect
from pathlib import Path

class ValkeyAuditModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary directory for test files
        #cls.temp_dir_obj = tempfile.TemporaryDirectory()
        cls.temp_dir = tempfile.mkdtemp(prefix="vka-")
        print(f"Temporary directory created: {cls.temp_dir}")
        #cls.log_file = os.path.join(cls.temp_dir.name, "audit.log")
        cls.log_file = os.path.join(cls.temp_dir, "audit.log")
        
        # Path to Valkey server and module
        cls.valkey_server = os.environ.get("VALKEY_SERVER", "valkey-server")
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH", "./audit.so")
        
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
        
        # Clean up temporary directory
        ########cls.temp_dir.cleanup()
    
    @classmethod
    def _start_valkey_server(cls):
        """Start a Valkey server instance for testing"""
        # Find an available port
        import socket
        s = socket.socket()
        s.bind(('', 0))
        cls.port = s.getsockname()[1]
        s.close()
        
        # Create configuration file
        #cls.conf_file = os.path.join(cls.temp_dir.name, "valkey.conf")
        cls.conf_file = os.path.join(cls.temp_dir, "valkey.conf")
        with open(cls.conf_file, 'w') as f:
            f.write(f"port {cls.port}\n")
            f.write(f"loadmodule {cls.module_path} protocol file logfile {cls.log_file}\n")
        
        print(f"written {cls.temp_dir} valkey.conf")

        # Start the server
        cls.server_proc = subprocess.Popen(
            [cls.valkey_server, cls.conf_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give it a moment to start
        time.sleep(1)
        #stdout, stderr = cls.server_proc.communicate()
        #if stdout:
        #    print(f"Server STDOUT:\n{stdout}")
        #if stderr:
        #    print(f"Server STDERR:\n{stderr}")

    @classmethod
    def _stop_valkey_server(cls):
        """Stop the Valkey server"""
        if hasattr(cls, 'server_proc'):
            cls.server_proc.terminate()
            cls.server_proc.wait(timeout=5)
    
    def _read_log_file(self):
        """Read the audit log file contents"""
        try:
            with open(self.log_file, 'r') as f:
                return f.readlines()
        except FileNotFoundError:
            return []
    
    def _clear_log_file(self):
        """Clear the contents of the audit log file"""
        open(self.log_file, 'w').close()
    
    def test_001_module_loaded(self):
        """Test that the audit module is loaded correctly"""
        module_list = self.redis.module_list()
        self.assertTrue(any(m["name"] == "audit" for m in module_list), 
                       "Audit module not found in loaded modules")
    
    def test_002_set_protocol_file(self):
        """Test setting the audit protocol to file"""
        # Create a new log file path
        #new_log_file = os.path.join(self.temp_dir.name, "new_audit.log")
        new_log_file = os.path.join(self.temp_dir, "new_audit.log")
        
        # Set the protocol to file with the new path
        result = self.redis.execute_command("AUDIT.SETPROTOCOL", "file", new_log_file)
        self.assertEqual(result, "OK", "Failed to set protocol to file")
        
        # Write something to trigger an audit event
        self.redis.set("test_key", "test_value")
        
        # Check if the new log file was created
        self.assertTrue(os.path.exists(new_log_file), 
                       f"New log file {new_log_file} was not created")
        
        # Check if there's content in the new log file
        with open(new_log_file, 'r') as f:
            log_content = f.read()
        
        self.assertTrue(len(log_content) > 0, 
                       "No audit log entries were written to the new log file")
    
    def test_003_set_format(self):
        """Test setting different audit log formats"""
        formats = ["text", "json", "csv"]
        
        # Set the protocol to file with the log_file
        result = self.redis.execute_command("AUDIT.SETPROTOCOL", "file", self.log_file)
        self.assertEqual(result, "OK", "Failed to set protocol to file")

        for fmt in formats:
            # Set the format
            result = self.redis.execute_command("AUDIT.SETFORMAT", fmt)
            self.assertEqual(result, "OK", f"Failed to set format to {fmt}")
            
            # Clear the log file
            self._clear_log_file()
            
            # Generate an event
            self.redis.set("format_test_key", "value")
            
            # Read the log file
            log_lines = self._read_log_file()
            self.assertTrue(len(log_lines) > 0, f"No log entries for format {fmt}")
            
            # Verify format
            if fmt == "json":
                # Check if the line is valid JSON
                try:
                    json_obj = json.loads(log_lines[0])
                    self.assertIn("timestamp", json_obj)
                    self.assertIn("category", json_obj)
                    self.assertIn("command", json_obj)
                except json.JSONDecodeError:
                    self.fail(f"Log line is not valid JSON: {log_lines[0]}")
            
            elif fmt == "csv":
                # Check if the line is valid CSV
                try:
                    reader = csv.reader(io.StringIO(log_lines[0]))
                    row = next(reader)
                    self.assertTrue(len(row) >= 3, "CSV should have at least 3 columns")
                except:
                    self.fail(f"Log line is not valid CSV: {log_lines[0]}")
            
            elif fmt == "text":
                # Check text format (simple check)
                self.assertRegex(log_lines[0], r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]",
                               "Text format should start with timestamp in brackets")
    
    def test_004_set_events(self):
        """Test enabling/disabling different event categories"""
        # Test setting specific events
        self.redis.execute_command("AUDIT.SETEVENTS", "config")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate different types of events
        self.redis.set("key1", "value1")  # Key operation - should NOT be logged
        self.redis.execute_command("CONFIG", "GET", "port")  # Config operation - should be logged
        
        # Check log file
        log_lines = self._read_log_file()
        
        # Only CONFIG events should be logged
        self.assertTrue(any("CONFIG" in line for line in log_lines), 
                       "CONFIG event was not logged")
        self.assertFalse(any("KEY_OP" in line for line in log_lines), 
                        "KEY_OP event was logged but should not be")
        
        # Test setting multiple events
        self.redis.execute_command("AUDIT.SETEVENTS", "config", "keys")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate events again
        self.redis.set("key2", "value2")
        self.redis.execute_command("CONFIG", "GET", "port")
        
        # Check log file
        log_lines = self._read_log_file()
        
        # Both CONFIG and KEY_OP events should be logged
        self.assertTrue(any("CONFIG" in line for line in log_lines), 
                       "CONFIG event was not logged")
        self.assertTrue(any("KEY_OP" in line for line in log_lines), 
                       "KEY_OP event was not logged")
        
        # Test disabling all events
        self.redis.execute_command("AUDIT.SETEVENTS", "none")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate events
        self.redis.set("key3", "value3")
        self.redis.execute_command("CONFIG", "GET", "port")
        
        # Check log file - should be empty
        log_lines = self._read_log_file()
        self.assertEqual(len(log_lines), 0, "Events were logged when all should be disabled")
        
        # Reset to all events for subsequent tests
        self.redis.execute_command("AUDIT.SETEVENTS", "all")
    
    def test_005_payload_options(self):
        """Test payload logging options"""
        # Set a reasonable payload size
        self.redis.execute_command("AUDIT.SETPAYLOADOPTIONS", "maxsize", "10")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate key operation with large payload
        self.redis.set("payload_key", "abcdefghijklmnopqrstuvwxyz")
        
        # Check log file - payload should be truncated
        log_lines = self._read_log_file()
        payload_line = next((line for line in log_lines if "payload_key" in line), None)
        self.assertIsNotNone(payload_line, "Key operation was not logged")
        
        # Should contain truncated payload (only first 10 chars)
        if "payload=" in payload_line:
            # Extract payload
            payload_match = re.search(r'payload=(.*?)(?:\s|$|\.\.\.|")', payload_line)
            if payload_match:
                payload = payload_match.group(1).strip()
                # JSON format might have quotes
                payload = payload.strip('"\'')
                self.assertTrue(len(payload) <= 10, 
                               f"Payload not truncated to maxsize (10): {payload}")
        
        # Test disabling payload logging
        self.redis.execute_command("AUDIT.SETPAYLOADOPTIONS", "disable", "yes")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate key operation
        self.redis.set("payload_key2", "test_value")
        
        # Check log file - should not contain payload
        log_lines = self._read_log_file()
        payload_line = next((line for line in log_lines if "payload_key2" in line), None)
        self.assertIsNotNone(payload_line, "Key operation was not logged")
        self.assertFalse("payload=" in payload_line, 
                        "Payload was logged despite being disabled")
        
        # Re-enable payload logging
        self.redis.execute_command("AUDIT.SETPAYLOADOPTIONS", "disable", "no")
    
    def test_006_get_config(self):
        """Test getting the current configuration"""
        config = self.redis.execute_command("AUDIT.GETCONFIG")
        
        # Check structure
        self.assertEqual(len(config), 5, "Config should have 5 sections")

        config_dict = {}
        for item in config:
            if len(item) == 2:
                key = item[0]
                value = item[1]
                if key == 'events' or key == 'payload':
                    # Process nested list of key-value pairs
                    nested_dict = {}
                    if isinstance(value, list):
                        for sub_item in value:
                            if len(sub_item) == 2:
                                sub_key = sub_item[0]
                                sub_value = sub_item[1]
                                nested_dict[sub_key] = sub_value
                    config_dict[key] = nested_dict
                elif isinstance(value, list) and len(value) == 2 and isinstance(value[0], str):
                    # Handle cases like ['file', '/path/to/file']
                    config_dict[key] = {value[0]: value[1]}
                else:
                    config_dict[key] = value
            else:
                print(f"Warning: Skipping malformed item: {item}")

        
        # Check for required sections
        required_sections = ["protocol", "format", "events", "payload"]
        for section in required_sections:
            self.assertIn(section, config_dict, f"Config missing section: {section}")
        
        # Check protocol
        protocol_info = config_dict["protocol"]
        self.assertEqual(list(protocol_info.keys())[0], "file", "Protocol key should be 'file'")
        
        # Check format (we left it at whatever the last test set it to)
        format_value = config_dict["format"]
        self.assertIn(format_value, ["text", "json", "csv"], 
                     f"Invalid format value: {format_value}")
        
        # Check events (we left it at "all" from previous test)
        events = config_dict["events"]
        events_dict = {}
        for key, value in events.items():
            events_dict[key] = value
        
        expected_events = ["connections", "auth", "config", "keys"]
        for event in expected_events:
            self.assertIn(event, events_dict, f"Missing event in config: {event}")
        
        # Check payload options
        payload_options = config_dict["payload"]
        payload_dict = {}
        for key, value in payload_options.items():
            payload_dict[key] = value
        
        expected_options = ["disable", "maxsize"]
        for option in expected_options:
            self.assertIn(option, payload_dict, f"Missing payload option: {option}")


if __name__ == "__main__":
    unittest.main(verbosity=2)