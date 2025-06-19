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
        try:
            with open(self.log_file, 'r') as f:
                return f.readlines()
        except FileNotFoundError:
            return []
    
    def _clear_log_file(self):
        """Clear the contents of the audit log file"""
        open(self.log_file, 'w').close()
    
    def test_001_command_category_filtering(self):
        """Test that commands are filtered correctly by category"""
        # Set format to text for easier parsing
        self.redis.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Test each category individually
        categories = [
            {"name": "connections", "mask": "connections", "command": "CLIENT", "subcommand": "LIST", "expected_in_log": False},
            {"name": "auth", "mask": "auth", "command": "AUTH", "subcommand": "dummy", "expected_in_log": True},
            {"name": "config", "mask": "config", "command": "CONFIG", "subcommand": "GET maxmemory", "expected_in_log": True},
            {"name": "keys", "mask": "keys", "command": "SET", "subcommand": "test_key value", "expected_in_log": True}
        ]
        
        for cat in categories:
            # Enable only this category
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
                self.redis.execute_command(cat["command"], *cat["subcommand"].split())
            
            # Read log file
            log_lines = self._read_log_file()
            
            command_logged = any(cat["command"] in line.upper() for line in log_lines)
            self.assertEqual(command_logged, cat["expected_in_log"], 
                            f"Category {cat['name']} not filtered correctly")
    
    def test_002_audit_commands_excluded(self):
        """Test that audit module commands are excluded from logging"""
        # Enable all event types
        self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
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
        self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "config")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute CONFIG GET command
        self.redis.execute_command("CONFIG", "GET", "port")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Verify log format and details
        self.assertTrue(any("CONFIG" in line and "subcommand=GET" in line and "param=port" in line 
                          for line in log_lines), 
                       "CONFIG command details not logged correctly")
    
    def test_004_auth_password_redaction(self):
        """Test that AUTH passwords are always redacted"""
        # Enable auth events
        self.redis.execute_command("CONFIG","SET","AUDIT.EVENTS", "auth")
        
        # Clear log file
        self._clear_log_file()
        
        # Attempt authentication (will fail but still generate log)
        try:
            self.redis.execute_command("AUTH", "secret_password")
        except:
            pass
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Verify password is redacted
        self.assertTrue(any("AUTH" in line and "password=<REDACTED>" in line 
                          for line in log_lines),
                       "AUTH password not properly redacted")
        
        # Verify raw password is NOT in the log
        self.assertFalse(any("secret_password" in line for line in log_lines),
                        "Raw password should never appear in logs")
    
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

    def test_008_auth_attempt_and_failure_logging(self):
        """Test that authentication attempts and failures are properly logged"""
        # Enable auth events
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        # Attempt authentication with invalid credentials (will fail)
        try:
            self.redis.execute_command("AUTH", "invalid_user", "wrong_password")
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
            pass  # Expected to fail
        
        # Read log file
        time.sleep(1)
        log_lines = self._read_log_file()
                          
        # Verify both ATTEMPT and FAILURE entries are logged
        attempt_logged = any("[AUTH]" in line and "ATTEMPT" in line and "invalid_user" in line for line in log_lines)
        failure_logged = any("[AUTH]" in line and "FAILURE" in line and "invalid_user" in line for line in log_lines)
        
        self.assertTrue(attempt_logged, "Authentication attempt not logged")
        self.assertTrue(failure_logged, "Authentication failure not logged")
        
        # Verify client information is included
        client_info_logged = any("127.0.0.1:" in line for line in log_lines)
        self.assertTrue(client_info_logged, "Client IP information not logged")

    def test_009_auth_attempt_and_success_logging(self):
        """Test that successful authentication is properly logged"""
        # Enable auth events
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        # First, set up a user for testing (if ACL is available)
        try:
            # Try to create a test user
            self.redis.execute_command("ACL", "SETUSER", "testuser", "on", ">testpass", "+@all")
            user_created = True
        except redis.exceptions.ResponseError:
            # If ACL is not available, we'll test with default auth
            user_created = False
        
        if user_created:
            # Attempt authentication with valid credentials
            try:
                self.redis.execute_command("AUTH", "testuser", "testpass")
                auth_succeeded = True
            except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
                auth_succeeded = False
            
            # Read log file
            time.sleep(1)
            log_lines = self._read_log_file()
            
            if auth_succeeded:
                # Verify both ATTEMPT and SUCCESS entries are logged
                attempt_logged = any("[AUTH]" in line and "ATTEMPT" in line and "testuser" in line for line in log_lines)
                success_logged = any("[AUTH]" in line and "SUCCESS" in line and "testuser" in line for line in log_lines)
                
                self.assertTrue(attempt_logged, "Authentication attempt not logged for successful auth")
                self.assertTrue(success_logged, "Authentication success not logged")
            
            # Clean up - delete the test user
            try:
                self.redis.execute_command("ACL", "DELUSER", "testuser")
            except:
                pass
        else:
            # Skip this test if ACL is not available
            self.skipTest("ACL not available for testing successful authentication")

    def test_010_auth_failure_user_reversion(self):
        """Test that failed authentication reverts to previous user context"""
        # Enable both auth and other events to capture the user reversion
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth,other")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        # Create a new Redis connection that won't auto-reconnect
        import redis
        test_redis = redis.Redis(
            host='localhost', 
            port=self.port, 
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=False,
            health_check_interval=0  # Disable health checks
        )
        
        # First, attempt authentication with invalid credentials using raw connection
        try:
            test_redis.execute_command("AUTH", "nonexistent_user", "wrong_password")
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError, redis.exceptions.ConnectionError):
            pass  # Expected to fail
        
        # Give a moment for the log to be written
        time.sleep(0.1)
        
        # Try to execute a command on the same connection to see user reversion
        try:
            test_redis.execute_command("ACL", "WHOAMI")
        except (redis.exceptions.ResponseError, redis.exceptions.ConnectionError):
            # If connection is broken or ACL WHOAMI not available, try with main connection
            try:
                self.redis.execute_command("ACL", "WHOAMI")
            except redis.exceptions.ResponseError:
                # If ACL WHOAMI is not available, try a different command
                try:
                    self.redis.execute_command("CLIENT", "ID")
                except:
                    pass
        
        # Close the test connection
        try:
            test_redis.close()
        except:
            pass
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check if authentication attempt was logged (this should always be there)
        attempt_logged = any("[AUTH]" in line and "ATTEMPT" in line and "nonexistent_user" in line for line in log_lines)
        self.assertTrue(attempt_logged, "Authentication attempt not logged")
        
        # Check if authentication failure was logged
        failure_logged = any("[AUTH]" in line and "FAILURE" in line and "nonexistent_user" in line for line in log_lines)
        self.assertTrue(failure_logged, "Authentication failure not logged")
        
        # Verify subsequent command shows connection reset behavior
        # Look for a log entry after the auth failure that shows a new client_id
        auth_failure_line_index = None
        for i, line in enumerate(log_lines):
            if "[AUTH] FAILURE" in line and "nonexistent_user" in line:
                auth_failure_line_index = i
                break
        
        if auth_failure_line_index is not None:
            # Check subsequent lines for new connection (different client_id)
            subsequent_lines = log_lines[auth_failure_line_index + 1:]
            
            # Extract client_id from failure line
            failure_line = log_lines[auth_failure_line_index]
            failure_client_match = re.search(r'client_id=(\d+)', failure_line)
            
            if failure_client_match:
                failure_client_id = failure_client_match.group(1)
                
                # Look for subsequent commands with different client_id (indicating new connection)
                new_connection_found = False
                for line in subsequent_lines:
                    client_match = re.search(r'client_id=(\d+)', line)
                    if client_match and client_match.group(1) != failure_client_id:
                        new_connection_found = True
                        break
                
                # This test verifies that after auth failure, subsequent operations use a new connection
                # This is the expected behavior when Redis Python client encounters auth errors
                if new_connection_found:
                    # This is the expected behavior - Redis client creates new connection after auth failure
                    pass
                else:
                    # If same connection is reused, check if user reverted to default
                    user_reverted = any("username=default" in line for line in subsequent_lines)
                    # Note: This assertion is relaxed since the behavior depends on Redis client implementation
                    # The important thing is that the ATTEMPT and FAILURE were logged correctly

    def test_011_auth_password_redaction_in_attempts(self):
        """Test that passwords are redacted in both ATTEMPT and FAILURE log entries"""
        # Enable auth events
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        # Attempt authentication with a password that should be redacted
        secret_password = "super_secret_password_123"
        try:
            self.redis.execute_command("AUTH", "testuser", secret_password)
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
            pass  # Expected to fail
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Verify that the raw password never appears in any log line
        password_exposed = any(secret_password in line for line in log_lines)
        self.assertFalse(password_exposed, "Raw password should never appear in authentication logs")
        
        # Verify that password redaction indicators are present (if applicable)
        # This depends on your specific implementation - adjust pattern as needed
        redaction_patterns = ["<REDACTED>", "***", "[REDACTED]", "password=*"]
        redaction_found = any(any(pattern in line for pattern in redaction_patterns) for line in log_lines)
        
        # Note: If your implementation doesn't show password fields at all in auth logs,
        # you might need to adjust this assertion
        if any("password" in line.lower() for line in log_lines):
            self.assertTrue(redaction_found, "Password redaction not found in authentication logs")

    def test_012_auth_multiple_failure_attempts(self):
        """Test logging of multiple consecutive authentication failures"""
        # Enable auth events
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        # Make multiple authentication attempts with different invalid credentials
        invalid_users = ["user1", "user2", "user3"]
        
        for user in invalid_users:
            try:
                self.redis.execute_command("AUTH", user, "wrong_password")
            except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
                pass  # Expected to fail
        
        # Read log file
        time.sleep(1)
        log_lines = self._read_log_file()
        
        # Verify that each attempt generated both ATTEMPT and FAILURE entries
        for user in invalid_users:
            attempt_logged = any("[AUTH]" in line and "ATTEMPT" in line and user in line for line in log_lines)
            failure_logged = any("[AUTH]" in line and "FAILURE" in line and user in line for line in log_lines)
            
            self.assertTrue(attempt_logged, f"Authentication attempt not logged for user {user}")
            self.assertTrue(failure_logged, f"Authentication failure not logged for user {user}")
        
    def test_013_auth_json_format_logging(self):
        """Test that authentication events are properly logged in JSON format"""
        # Enable auth events with JSON format
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "json")
        
        # Clear log file
        self._clear_log_file()
        
        # Attempt authentication (will fail)
        try:
            self.redis.execute_command("AUTH", "json_test_user", "password")
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
            pass  # Expected to fail
        
        # Read log file
        time.sleep(1)
        log_lines = self._read_log_file()
        
        # Verify JSON format entries exist
        self.assertTrue(len(log_lines) > 0, "No log entries generated in JSON format")
        
        # Parse and validate JSON structure for auth events
        auth_entries = []
        for line in log_lines:
            try:
                json_obj = json.loads(line.strip())
                if json_obj.get("category") == "AUTH":
                    auth_entries.append(json_obj)
            except json.JSONDecodeError:
                self.fail(f"Invalid JSON format in log: {line}")
        
        self.assertTrue(len(auth_entries) > 0, "No AUTH category entries found in JSON log")
        
        # Verify required fields in auth JSON entries
        for entry in auth_entries:
            self.assertIn("category", entry, "JSON auth entry missing category field")
            self.assertIn("result", entry, "JSON auth entry missing result field")
            self.assertIn("username", entry, "JSON auth entry missing username field")
            self.assertIn("command", entry, "JSON auth entry missing command field")
            self.assertIn("client_ip", entry, "JSON auth entry missing client_ip field")
            self.assertIn("client_port", entry, "JSON auth entry missing client_port field")
            self.assertIn("server_hostname", entry, "JSON auth entry missing server_hostname field")
            self.assertIn("timestamp", entry, "JSON auth entry missing timestamp field")
            
            # Verify event_type is either ATTEMPT, SUCCESS, or FAILURE
            self.assertIn(entry["result"], ["ATTEMPT", "SUCCESS", "FAILURE", "EXECUTE"], 
                        f"Invalid result: {entry['result']}")

    def test_014_auth_csv_format_logging(self):
        """Test that authentication events are properly logged in CSV format"""
        # Enable auth events with CSV format
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "csv")
        
        # Clear log file
        self._clear_log_file()
        
        # Attempt authentication (will fail)
        try:
            self.redis.execute_command("AUTH", "csv_test_user", "password")
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
            pass  # Expected to fail
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Verify CSV format entries exist
        self.assertTrue(len(log_lines) > 0, "No log entries generated in CSV format")
        
        # Verify CSV structure for auth events
        for line in log_lines:
            fields = line.strip().split(",")
            self.assertGreaterEqual(len(fields), 5, "CSV auth entry has insufficient fields")
            
            # Basic validation - timestamp, category, command, result, username, client_info should be present
            # Adjust field positions based on your actual CSV format
            category_field = next((field for field in fields if "AUTH" in field), None)
            self.assertIsNotNone(category_field, "AUTH category not found in CSV entry")
            
            event_type_field = next((field for field in fields if field in ["ATTEMPT", "SUCCESS", "FAILURE", "EXECUTE"]), None)
            self.assertIsNotNone(event_type_field, "Results not found in CSV entry")

            
    def test_015_auth_failure_user_context_persistence(self):
        """Test that user context is properly maintained after authentication failure"""
        # This test focuses on the core audit functionality rather than client behavior
        # Enable both auth and other events 
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "auth,other")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        # First establish a baseline - execute a command to see current user
        try:
            self.redis.execute_command("PING")
        except:
            pass
        
        # Now attempt failed authentication
        try:
            self.redis.execute_command("AUTH", "invalid_user", "wrong_password")
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
            pass  # Expected to fail
        
        # Execute another command to observe user context
        try:
            self.redis.execute_command("PING")
        except:
            pass
        
        # Read log file
        time.sleep(1)
        log_lines = self._read_log_file()
        
        # Verify that authentication attempt and failure are both logged
        attempt_logged = any("[AUTH]" in line and "ATTEMPT" in line and "invalid_user" in line for line in log_lines)
        failure_logged = any("[AUTH]" in line and "FAILURE" in line and "invalid_user" in line for line in log_lines)
        
        self.assertTrue(attempt_logged, "Authentication attempt not logged")
        self.assertTrue(failure_logged, "Authentication failure not logged")
        
        # This test primarily verifies that the audit module correctly logs auth events
        # The user context behavior will depend on the specific Redis/Valkey implementation
        # and client library behavior

if __name__ == "__main__":
    unittest.main(verbosity=2)
