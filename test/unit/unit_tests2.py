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
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH",
            os.path.join(os.path.dirname(__file__), "..", "..", "libvalkeyaudit.so"))
        
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

        # Probe whether the server supports command result events.
        # Trigger a known WRONGTYPE failure and check if the audit log captures it.
        open(cls.log_file, 'w').close()
        cls.redis.execute_command("CONFIG", "SET", "audit.events", "keys")
        cls.redis.set("__probe__", "string")
        try:
            cls.redis.lpush("__probe__", "val")
        except Exception:
            pass
        time.sleep(0.5)
        try:
            with open(cls.log_file) as f:
                cls.command_result_supported = len(f.read()) > 0
        except FileNotFoundError:
            cls.command_result_supported = False
        open(cls.log_file, 'w').close()
        cls.redis.delete("__probe__")
    
    @classmethod
    def tearDownClass(cls):
        # Stop the server
        cls._stop_valkey_server()
        
        # Clean up temporary directory
        ########cls.temp_dir.cleanup()
    
    def setUp(self):
        """Set up a unique log file for each test"""
        if not self.__class__.command_result_supported:
            self.skipTest(
                "Server does not support command result events "
                "(requires Valkey build with PR #2936)"
            )

        # Get the current test method name
        test_name = self._testMethodName

        # Create a unique log file for this test
        self.test_log_file = os.path.join(self.temp_dir, f"{test_name}.log")

        # Configure the audit module to use this log file
        try:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "file " + self.test_log_file)
            print(f"Test {test_name} using log file: {self.test_log_file}")
        except Exception as e:
            print(f"Warning: Could not set audit protocol for {test_name}: {e}")

        # Allow time for configuration to take effect
        time.sleep(0.2)
    
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
            f.write(f"audit.command_result_mode all\n")

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
            if cls.server_proc.stdout:
                cls.server_proc.stdout.close()
            if cls.server_proc.stderr:
                cls.server_proc.stderr.close()

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
            time.sleep(0.4)
            log_lines = self._read_log_file()

            for line in log_lines:
                print(f"Log line : {line.strip()}")

            command_logged = any(cat["command"] in line.upper() for line in log_lines)
            log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
            self.assertEqual(command_logged, cat["expected_in_log"],
                            f"Category '{cat['name']}': expected logged={cat['expected_in_log']}, "
                            f"got logged={command_logged}\nLog contents:\n  {log_summary}")

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
        time.sleep(0.4)
        log_lines = self._read_log_file()

        # Verify no "AUDIT" command was logged (to prevent recursion)
        audit_logged = any("AUDITUSERS" in line.upper() for line in log_lines)
        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        self.assertFalse(audit_logged,
            f"Audit commands should be excluded from logging\nLog contents:\n  {log_summary}")
    
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
        time.sleep(0.4)
        log_lines = self._read_log_file()
        for line in log_lines:
            print(f"Log line : {line.strip()}")

        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        self.assertTrue(
            any("CONFIG" in line and "subcommand=GET" in line and "param=port" in line
                for line in log_lines),
            f"CONFIG command details not logged correctly\n"
            f"Expected: CONFIG ... subcommand=GET ... param=port\n"
            f"Actual log:\n  {log_summary}"
        )
    
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
        time.sleep(0.4)
        log_lines = self._read_log_file()

        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        set_log_line = next((line for line in log_lines if "payload_test_key" in line), None)
        self.assertIsNotNone(set_log_line,
            f"SET operation not logged\nActual log:\n  {log_summary}")

        self.assertTrue("payload=" in set_log_line,
            f"Payload not included in log\nActual line: {set_log_line.strip()}")

        # Extract payload with regex and verify truncation
        payload_match = re.search(r'payload=([^\s]+)', set_log_line)
        if payload_match:
            payload = payload_match.group(1)
            raw_len = len(payload.replace("...(truncated)", ""))
            self.assertLessEqual(raw_len, 10,
                f"Payload not truncated to 10 chars\n"
                f"Expected: len <= 10\nActual payload: '{payload}' (raw len={raw_len})")

        # Now disable payload logging
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PAYLOAD_DISABLE", "yes")

        # Clear log file
        self._clear_log_file()

        # Create another key
        self.redis.set("payload_test_key2", "test_value")

        # Read log file
        time.sleep(0.4)
        log_lines = self._read_log_file()

        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        set_log_line = next((line for line in log_lines if "payload_test_key2" in line), None)
        self.assertIsNotNone(set_log_line,
            f"SET operation not logged (with payload disabled)\nActual log:\n  {log_summary}")

        self.assertFalse("payload=" in set_log_line,
            f"Payload should be excluded when disabled\nActual line: {set_log_line.strip()}")
    
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
        time.sleep(0.4)
        log_lines = self._read_log_file()

        config_logged = any("CONFIG" in line for line in log_lines)
        key_logged = any("multi_cat_test" in line for line in log_lines)
        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"

        self.assertTrue(config_logged,
            f"CONFIG command not logged with multiple categories enabled\n"
            f"Actual log:\n  {log_summary}")
        self.assertTrue(key_logged,
            f"Key operation 'multi_cat_test' not logged with multiple categories enabled\n"
            f"Actual log:\n  {log_summary}")
    
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
            time.sleep(0.4)
            log_lines = self._read_log_file()
            self.assertTrue(len(log_lines) > 0,
                f"No log entry generated for format '{fmt}' "
                f"(key: format_test_{fmt})")
            
            # Basic check that the format looks right
            first_line = log_lines[0].strip()
            if fmt == "json":
                try:
                    json_obj = json.loads(first_line)
                    for field in ("category", "command", "command_args", "error"):
                        self.assertIn(field, json_obj,
                            f"JSON format missing '{field}' field\nActual: {first_line}")
                except json.JSONDecodeError:
                    self.fail(f"Invalid JSON format in log\nActual: {first_line}")
            elif fmt == "csv":
                import csv as _csv, io as _io
                fields = next(_csv.reader(_io.StringIO(first_line)))
                self.assertGreaterEqual(len(fields), 3,
                    f"CSV format has too few fields (got {len(fields)})\n"
                    f"Actual: {first_line}")
            elif fmt == "text":
                self.assertRegex(first_line, r"\[\w+\]",
                    f"Text format missing category in brackets\nActual: {first_line}")
    
    def test_008_json_command_args_key_op(self):
        """JSON command_args for a SET should contain key= (and payload= when enabled)."""
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "json")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "keys")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.PAYLOAD_DISABLE", "no")
        self._clear_log_file()

        self.redis.set("json_args_key_test", "myvalue")

        time.sleep(0.4)
        log_lines = self._read_log_file()

        obj = None
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if "json_args_key_test" in o.get("command_args", ""):
                    obj = o
                    break
            except json.JSONDecodeError:
                continue

        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        self.assertIsNotNone(obj,
            f"No JSON entry with key=json_args_key_test found\nLog:\n  {log_summary}")
        self.assertIn("key=json_args_key_test", obj["command_args"],
            f"command_args should contain 'key=json_args_key_test', got: {obj['command_args']!r}")
        self.assertIn("payload=myvalue", obj["command_args"],
            f"command_args should contain 'payload=myvalue', got: {obj['command_args']!r}")
        self.assertEqual(obj["error"], "",
            f"error should be empty for a successful SET, got: {obj['error']!r}")

    def test_009_json_command_args_config(self):
        """JSON command_args for CONFIG GET should contain subcommand= and param=."""
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "json")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "config")
        self._clear_log_file()

        self.redis.execute_command("CONFIG", "GET", "maxmemory")

        time.sleep(0.4)
        log_lines = self._read_log_file()

        obj = None
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if "subcommand=" in o.get("command_args", ""):
                    obj = o
                    break
            except json.JSONDecodeError:
                continue

        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        self.assertIsNotNone(obj,
            f"No JSON entry with subcommand= found\nLog:\n  {log_summary}")
        args = obj["command_args"]
        self.assertIn("subcommand=GET", args,
            f"command_args should contain 'subcommand=GET', got: {args!r}")
        self.assertIn("param=maxmemory", args,
            f"command_args should contain 'param=maxmemory', got: {args!r}")

    def test_010_json_client_id_is_integer(self):
        """JSON client_id should be a positive integer, not an IP address."""
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "json")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "keys")
        self._clear_log_file()

        self.redis.set("client_id_int_test", "value")

        time.sleep(0.4)
        log_lines = self._read_log_file()

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "client_id_int_test" in obj.get("command_args", ""):
                self.assertIsInstance(obj["client_id"], int,
                    f"client_id should be an integer, got {type(obj['client_id']).__name__}: {obj['client_id']!r}")
                self.assertGreater(obj["client_id"], 0,
                    "client_id should be a positive integer")
                return
        self.fail("No log entry found for client_id_int_test SET command")

    def test_011_text_named_fields(self):
        """TEXT format should include all named field=value pairs."""
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "keys")
        self._clear_log_file()

        self.redis.set("text_named_fields_test", "value")

        time.sleep(0.4)
        log_lines = self._read_log_file()

        line = next((l for l in log_lines if "text_named_fields_test" in l), None)
        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        self.assertIsNotNone(line,
            f"SET command not found in log\nLog:\n  {log_summary}")

        for pattern in (r"result=\w+", r"duration_us=\d+", r"keys_modified=\d+",
                        r"client_id=\d+", r"username=\S+", r"client_ip=[\d.]+"):
            self.assertRegex(line, pattern,
                f"TEXT format missing field matching '{pattern}'\nLine: {line.strip()}")

    def test_012_csv_field_order(self):
        """CSV columns should follow the documented order with correct types."""
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "csv")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "keys")
        self._clear_log_file()

        self.redis.set("csv_order_test", "value")

        time.sleep(0.4)
        log_lines = self._read_log_file()

        row = None
        for line in log_lines:
            if "csv_order_test" in line:
                import csv as _csv, io as _io
                row = next(_csv.reader(_io.StringIO(line.strip())))
                break

        log_summary = "\n  ".join(l.strip() for l in log_lines) if log_lines else "(empty)"
        self.assertIsNotNone(row,
            f"SET command not found in CSV log\nLog:\n  {log_summary}")
        self.assertGreaterEqual(len(row), 13,
            f"CSV should have 13+ columns, got {len(row)}: {row}")

        # timestamp,category,command,command_args,result,duration_us,keys_modified,
        # client_id,username,client_ip,client_port,server_hostname,error
        self.assertRegex(row[0], r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
            f"col 0 (timestamp) malformed: {row[0]!r}")
        self.assertIn("key=csv_order_test", row[3],
            f"col 3 (command_args) should contain key=csv_order_test: {row[3]!r}")
        self.assertEqual(row[4], "SUCCESS",
            f"col 4 (result) should be SUCCESS: {row[4]!r}")
        self.assertTrue(row[5].isdigit(),
            f"col 5 (duration_us) should be numeric: {row[5]!r}")
        self.assertTrue(row[6].isdigit(),
            f"col 6 (keys_modified) should be numeric: {row[6]!r}")
        self.assertTrue(row[7].isdigit(),
            f"col 7 (client_id) should be numeric: {row[7]!r}")
        self.assertEqual(row[12], "",
            f"col 12 (error) should be empty for a successful SET: {row[12]!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)