#!/usr/bin/env python3
import unittest
import redis
import os
import tempfile
import time
import json
import re
from pathlib import Path

class ValkeyAuditCommandLoggerTests(unittest.TestCase):
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
    
    def setUp(self):
        """Set up a unique log file for each test"""
        # Get the current test method name
        test_name = self._testMethodName
        
        # Create a unique log file for this test
        self.test_log_file = os.path.join(self.temp_dir, f"{test_name}.log")
        
        # Configure the audit module to use this log file
        try:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "file "+ self.test_log_file)
            print(f"Test {test_name} using log file: {self.test_log_file}")
        except Exception as e:
            print(f"Warning: Could not set audit protocol for {test_name}: {e}")
        
        # Small delay to ensure configuration is applied
        time.sleep(0.1)
    
    def tearDown(self):
        """Clean up after each test"""
        # Optionally remove the test log file if you want to save space
        # Commented out to keep logs for debugging
        # if hasattr(self, 'test_log_file') and os.path.exists(self.test_log_file):
        #     os.remove(self.test_log_file)
        pass
    
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
            f.write(f"loglevel debug\n")
            #f.write(f"loadmodule {cls.module_path} protocol file {cls.log_file}\n")
            f.write(f"loadmodule {cls.module_path}\n")    
            f.write(f"audit.protocol file {cls.log_file}\n")

        # Start the server with subprocess
        import subprocess
        cls.server_proc = subprocess.Popen(
            [cls.valkey_server, cls.conf_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give it a moment to start
        time.sleep(1)
    
    @classmethod
    def _stop_valkey_server(cls):
        """Stop the Valkey server"""
        if hasattr(cls, 'server_proc'):
            cls.server_proc.terminate()
            cls.server_proc.wait(timeout=5)
    
    def _read_log_file(self):
        """Read the audit log file contents"""
        # Use test-specific log file if available, otherwise fall back to class log file
        log_file_to_read = getattr(self, 'test_log_file', self.log_file)
        try:
            with open(log_file_to_read, 'r') as f:
                return f.readlines()
        except FileNotFoundError:
            return []
    
    def _clear_log_file(self):
        """Clear the contents of the audit log file"""
        # Use test-specific log file if available, otherwise fall back to class log file
        log_file_to_clear = getattr(self, 'test_log_file', self.log_file)
        open(log_file_to_clear, 'w').close()
    
    def test_001_command_category_filtering(self):
        """Test that commands are filtered correctly by category"""
        # Set format to text for easier parsing
        self.redis.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Test each category individually
        categories = [
            {"name": "connections", "mask": "connections", "command": "CLIENT", "subcommand": "LIST", "expected_in_log": False},
            {"name": "keys", "mask": "keys", "command": "SET", "subcommand": "test_key value", "expected_in_log": True},
            {"name": "config", "mask": "config", "command": "CONFIG", "subcommand": "GET maxmemory", "expected_in_log": True}
            #,{"name": "auth", "mask": "auth", "command": "AUTH", "subcommand": "dummy", "expected_in_log": True},
        ]
        
        for cat in categories:
            # Enable only this category
            print(f"Testing category: {cat['name']}")
            self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", cat["mask"])
                        
            # Clear log file
            self._clear_log_file()
            
            # Execute command
            if cat["command"] == "AUTH":
                try:
                    # AUTH will likely fail, but we just want to generate the event
                    self.redis.execute_command(cat["command"], cat["subcommand"])
                except:
                    pass
            else:
                result = self.redis.execute_command("CONFIG","GET","audit.events")
                print(f"Executed command result: {result}")
                result = self.redis.execute_command(cat["command"], *cat["subcommand"].split())
                print(f"Executed command result: {result}")
            
            # Read log file
            log_lines = self._read_log_file()

            for line in log_lines:
                print(f"Log line : {line.strip()}")
            
            command_logged = any(cat["command"] in line.upper() for line in log_lines)
            self.assertEqual(command_logged, cat["expected_in_log"], 
                            f"Category {cat['name']} not filtered correctly")

    def test_002_audit_commands_excluded(self):
        """Test that audit module commands are excluded from logging"""
        # Enable all event types
        result = self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        print(f"Executed command result: {result}")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute an audit command
        self.redis.execute_command("AUDITUSERS")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Verify no "AUDIT" command was logged (to prevent recursion)
        audit_logged = any("AUDITUSERS" in line.upper() for line in log_lines)
        self.assertFalse(audit_logged, "Audit commands should be excluded from logging")
    
    def test_003_config_command_details(self):
        """Test that CONFIG commands are logged with appropriate details"""
        # Enable only config events
        result = self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "config")
        print(f"Executed command result: {result}")

        # Clear log file
        self._clear_log_file()
        
        # Execute CONFIG GET command
        self.redis.execute_command("CONFIG", "GET", "port")
        
        # Read log file
        log_lines = self._read_log_file()
        for line in log_lines:
            print(f"Log line : {line.strip()}")

        
        # Verify log format and details
        self.assertTrue(any("CONFIG" in line and "subcommand=GET" in line and "param=port" in line 
                          for line in log_lines), 
                       "CONFIG command details not logged correctly")
    
    def test_005_key_operation_payload_handling(self):
        """Test payload handling for key operations"""
        # Enable key events
        self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "keys")
        
        # Set a small payload size limit
        self.redis.execute_command("CONFIG","SET","AUDIT.PAYLOAD_MAXSIZE", "10")
        
        # Clear log file
        self._clear_log_file()
        
        # Create a key with a large value
        large_value = "abcdefghijklmnopqrstuvwxyz"
        self.redis.set("payload_test_key", large_value)
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Find the log line for our SET operation
        set_log_line = next((line for line in log_lines if "payload_test_key" in line), None)
        self.assertIsNotNone(set_log_line, "SET operation not logged")
        
        # Verify payload is truncated
        # The actual content depends on log format, but should contain the first 10 chars
        # and indicate truncation
        self.assertTrue("payload=" in set_log_line, "Payload not included in log")
        
        # Extract payload with regex
        payload_match = re.search(r'payload=([^\s]+)', set_log_line)
        if payload_match:
            payload = payload_match.group(1)
            # Should be truncated and possibly have truncation indicator
            self.assertLessEqual(len(payload.replace("...(truncated)", "")), 10, 
                               "Payload not truncated to configured size")
            
        # Now disable payload logging
        self.redis.execute_command("CONFIG","SET","AUDIT.PAYLOAD_DISABLE", "yes")
        
        # Clear log file
        self._clear_log_file()
        
        # Create another key
        self.redis.set("payload_test_key2", "test_value")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Find the log line for our second SET operation
        set_log_line = next((line for line in log_lines if "payload_test_key2" in line), None)
        self.assertIsNotNone(set_log_line, "SET operation not logged")
        
        # Verify payload is not included
        self.assertFalse("payload=" in set_log_line, "Payload should be excluded when disabled")
    
    def test_006_multiple_categories(self):
        """Test that multiple enabled categories work correctly"""
        # Enable both config and keys events
        self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "config,keys")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute both types of commands
        self.redis.execute_command("CONFIG", "GET", "port")
        self.redis.set("multi_cat_test", "value")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Verify both commands were logged
        config_logged = any("CONFIG" in line for line in log_lines)
        key_logged = any("multi_cat_test" in line for line in log_lines)
        
        self.assertTrue(config_logged, "CONFIG command not logged with multiple categories enabled")
        self.assertTrue(key_logged, "Key operation not logged with multiple categories enabled")
    
    def test_007_format_specific_logging(self):
        """Test that command logging works with different formats"""
        # Enable all event types
        self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        formats = ["text", "json", "csv"]
        
        for fmt in formats:
            # Set the format
            self.redis.execute_command("CONFIG","SET","AUDIT.FORMAT", fmt)
            
            # Clear log file
            self._clear_log_file()
            
            # Execute a key command
            self.redis.set(f"format_test_{fmt}", "value")
            
            # Read log file
            log_lines = self._read_log_file()
            self.assertTrue(len(log_lines) > 0, f"No log entry generated for format {fmt}")
            
            # Basic check that the format looks right
            if fmt == "json":
                try:
                    json_obj = json.loads(log_lines[0])
                    self.assertIn("category", json_obj, "JSON format missing category field")
                    self.assertIn("command", json_obj, "JSON format missing command field")
                    self.assertIn("details", json_obj, "JSON format missing details field")
                except json.JSONDecodeError:
                    self.fail(f"Invalid JSON format in log: {log_lines[0]}")
            elif fmt == "csv":
                # CSV should have at least 3 fields (timestamp, category, command)
                fields = log_lines[0].strip().split(",")
                self.assertGreaterEqual(len(fields), 3, "CSV format has too few fields")
            elif fmt == "text":
                # Text format should have category in brackets
                self.assertRegex(log_lines[0], r"\[\w+\]", "Text format missing category in brackets")
    
if __name__ == "__main__":
    unittest.main(verbosity=2)