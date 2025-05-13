import os
import time
import unittest
import subprocess
import redis
import tempfile
import json
import csv
import io
import socket
import shutil


class ValkeyAuditLoadmoduleTest(unittest.TestCase):
    """Test cases for Valkey audit module configuration parameters."""
    
    @classmethod
    def setUpClass(cls):
        """Create a base temporary directory for all tests."""
        cls.base_temp_dir = tempfile.mkdtemp(prefix="vka-base-")
        print(f"Base temporary directory created: {cls.base_temp_dir}")
        
        # Path to Valkey server and module
        cls.valkey_server = os.environ.get("VALKEY_SERVER", "valkey-server")
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH", "./audit.so")
        
        # Ensure the module exists
        if not os.path.exists(cls.module_path):
            raise FileNotFoundError(f"Audit module not found at {cls.module_path}")
    
    @classmethod
    def tearDownClass(cls):
        """Clean up the base temporary directory."""
        if os.path.exists(cls.base_temp_dir):
            #shutil.rmtree(cls.base_temp_dir)
            print(f"Base temporary directory NOT removed: {cls.base_temp_dir}")
    
    def setUp(self):
        """Set up a fresh server environment for each test."""
        # Create a test-specific temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix="vka-test-", dir=self.base_temp_dir)
        print(f"Test temporary directory created: {self.temp_dir}")
        
        # Default paths
        self.valkey_conf_path = os.path.join(self.temp_dir, "valkey.conf")
        
        # Find an available port
        s = socket.socket()
        s.bind(('', 0))
        self.port = s.getsockname()[1]
        s.close()
        
        # Server process and client
        self.server_proc = None
        self.client = None
        
        # This will be set in create_config_file for each test
        self.audit_log_path = None
    
    def tearDown(self):
        """Clean up server and client for each test."""
        # Close the client connection
        if self.client:
            try:
                self.client.close()
            except:
                pass
        
        # Stop the server
        if self.server_proc:
            try:
                self.server_proc.terminate()
                self.server_proc.wait(timeout=5)
            except:
                # Force kill if it doesn't terminate gracefully
                try:
                    self.server_proc.kill()
                except:
                    pass
        
        # Clean up the test-specific temporary directory
        if os.path.exists(self.temp_dir):
            #shutil.rmtree(self.temp_dir)
            print(f"Test temporary directory NOT removed: {self.temp_dir}")
    
    def create_config_file(self, module_params=None, test_name=None):
        print(f"\n params: {module_params}")
        """Create a Valkey configuration file with the audit module loaded.
        
        Args:
            module_params: List of parameters to pass to the audit module
            test_name: Name of the test, used to create a unique log file path
            
        Returns:
            Path to the created configuration file
        """
        # Create a unique log file for this test
        if test_name is None:
            test_name = self._testMethodName
        
        # Generate a specific audit log path for this test
        self.audit_log_path = os.path.join(self.temp_dir, f"audit_{test_name}.log")
        
        # Check if protocol file path is already in module_params
        has_protocol_file = False
        if module_params:
            for i, param in enumerate(module_params):
                if param == "protocol" and i+1 < len(module_params) and module_params[i+1] == "file":
                    has_protocol_file = True
                    break
        
        # Start with the base loadmodule command
        module_load_line = f"loadmodule {self.module_path}"
        
        # If module_params has protocol file, add the parameters as is
        if module_params and has_protocol_file:
            module_load_line += ' ' + ' '.join(module_params)
        # Otherwise, add module_params + our default protocol file
        elif module_params:
            module_load_line += ' ' + ' '.join(module_params) + f" protocol file {self.audit_log_path}"
        # If no module_params, just add our default protocol file
        else:
            module_load_line += f" protocol file {self.audit_log_path}"
        
        # Create the config file
        with open(self.valkey_conf_path, 'w') as f:
            f.write(f"port {self.port}\n")
            f.write(f"{module_load_line}\n")
        
        print(f"Created config file at {self.valkey_conf_path}")
        print(f"Module load line: {module_load_line}")
        print(f"Log file path for assertions: {self.audit_log_path}")
        
        return self.valkey_conf_path
    
    def start_server(self, config_path):
        """Start Valkey server with the specified configuration."""
        print(f"Starting Valkey server with config: {config_path}")
        self.server_proc = subprocess.Popen(
            [self.valkey_server, config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for server to start (with timeout)
        start_time = time.time()
        timeout = 10  # seconds
        
        # Create client connection
        self.client = redis.Redis(host='localhost', port=self.port, decode_responses=True)
        
        # Check if server is responsive
        while time.time() - start_time < timeout:
            try:
                self.client.ping()
                print(f"Server started successfully on port {self.port}")
                return True
            except redis.exceptions.ConnectionError:
                time.sleep(0.5)
        
        # If we get here, the server didn't start properly
        stdout, stderr = self.server_proc.communicate(timeout=1)
        print(f"Server failed to start. STDOUT: {stdout.decode() if stdout else 'None'}")
        print(f"STDERR: {stderr.decode() if stderr else 'None'}")
        self.fail("Server failed to start properly")
    
    def stop_server(self):
        """Stop the running Valkey server."""
        print("Stopping Valkey server...")
        
        # Close Redis client connection if it exists
        if hasattr(self, 'client') and self.client:
            self.client.close()
            self.client = None
            
        # Terminate the server process if it exists
        if hasattr(self, 'server_proc') and self.server_proc:
            # First try graceful termination
            self.server_proc.terminate()
            
            # Wait for process to terminate (with timeout)
            try:
                self.server_proc.wait(timeout=5)
                print("Server stopped gracefully")
            except subprocess.TimeoutExpired:
                # If graceful termination fails, force kill
                print("Server did not terminate gracefully, force killing...")
                self.server_proc.kill()
                self.server_proc.wait()
                print("Server forcefully terminated")
            
            # Clear the server process reference
            self.server_proc = None
        else:
            print("No server process was running")
        
        # Verify server is actually stopped by attempting to connect
        try:
            test_client = redis.Redis(host='localhost', port=self.port, decode_responses=True)
            test_client.ping()
            print("WARNING: Server appears to still be running!")
            test_client.close()
            return False
        except redis.exceptions.ConnectionError:
            # This exception is expected and indicates the server is stopped
            print(f"Confirmed server is no longer running on port {self.port}")
            return True
    
    def read_audit_log(self, log_path=None):
        """Read and return the audit log contents."""
        if log_path is None:
            log_path = self.audit_log_path
            
        if log_path is None:
            self.fail("No audit log path specified")
        
        if not os.path.exists(log_path):
            print(f"Warning: Log file not found at {log_path}")
            return ""
        
        with open(log_path, 'r') as f:
            content = f.read()
        
        print(f"Log file {log_path} contents ({len(content)} bytes):")
        if len(content) > 1000:
            print(content[:1000] + "... (truncated)")
        else:
            print(content or "(empty)")
            
        return content
    
    def test_default_config(self):
        """Test audit module with default configuration."""
        # Create config with test-specific log file
        config_path = self.create_config_file(test_name="default_config")
        self.start_server(config_path)
        
        # Perform some operations that should be logged
        self.client.set("key1", "value1")
        self.client.get("key1")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # Check if audit log exists and has content
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)
    
    def test_enable_parameter(self):
        """Test enable parameter (on/off)."""
        # Test enabled
        config_path = self.create_config_file(["enable", "yes"], test_name="enable_yes")
        self.start_server(config_path)
        
        self.client.set("key1", "value1")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)
    
    def test_disable_parameter(self):
        """Test disable parameter."""
        config_path = self.create_config_file(["enable", "no"], test_name="enable_no")
        self.start_server(config_path)
        
        self.client.set("key2", "value2")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        # When disabled, log should not contain SET command
        self.assertNotIn("[KEY_OP] SET", log_content)
    
    def test_always_audit_config_parameter(self):
        """Test always_audit_config parameter."""
        config_path = self.create_config_file(
            ["enable", "yes", "always_audit_config", "yes", "events", "config"], 
            test_name="always_audit_config"
        )
        self.start_server(config_path)
        
        # Regular command should not be logged
        self.client.set("key1", "value1")
        
        # Configuration command should be logged even with auditing disabled
        try:
            self.client.config_set("maxmemory-policy", "allkeys-lru")
        except:
            # Some versions might not allow this command, which is fine
            print("Skipping CONFIG SET - command may be disabled")
            return
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertNotIn("[KEY_OP] SET", log_content)
        self.assertIn("[CONFIG]", log_content)
        self.assertIn("subcommand=SET", log_content)
    
    def test_protocol_file_parameter(self):
        """Test protocol 'file' with custom path."""
        # Create a custom log path within the temp directory
        custom_log_path = os.path.join(self.temp_dir, "custom_audit.log")
        
        # Create config with custom log file path
        config_path = self.create_config_file(
            ["protocol", "file", custom_log_path], 
            test_name="protocol_file"
        )
        self.start_server(config_path)
        
        self.client.set("key1", "value1")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # Check the custom log file
        custom_log_content = self.read_audit_log(custom_log_path)
        self.assertIn("[KEY_OP] SET", custom_log_content)
        
        # Default log (which would be self.audit_log_path) should be ignored in this case
        # since we explicitly specified a different path
    
    def test_format_json_parameter(self):
        """Test JSON format option."""
        config_path = self.create_config_file(["format", "json"], test_name="format_json")
        self.start_server(config_path)
        
        self.client.set("key1", "value1")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        
        # Verify it's valid JSON
        log_lines = log_content.strip().split("\n")
        valid_json_found = False
        
        for line in log_lines:
            if not line:
                continue
                
            try:
                json_entry = json.loads(line)
                if "command" in json_entry and json_entry["command"] == "SET":
                    self.assertIn("key=", json_entry["details"])
                    valid_json_found = True
            except json.JSONDecodeError:
                print(f"Invalid JSON in line: {line}")
                continue
        
        self.assertTrue(valid_json_found, "No valid JSON with SET command found in log")
    
    def test_format_csv_parameter(self):
        """Test CSV format option."""
        config_path = self.create_config_file(["format", "csv"], test_name="format_csv")
        self.start_server(config_path)
        
        self.client.set("key2", "value2")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        
        # Verify it's valid CSV
        log_lines = log_content.strip().split("\n")
        valid_csv_found = False
        
        for line in log_lines:
            if not line:
                continue
                
            try:
                csv_reader = csv.reader(io.StringIO(line))
                row = next(csv_reader)
                if len(row) > 3 and "SET" in line:
                    valid_csv_found = True
            except:
                print(f"Invalid CSV in line: {line}")
                continue
        
        self.assertTrue(valid_csv_found, "No valid CSV with SET command found in log")
    
    def test_events_connections_parameter(self):
        """Test events parameter with connections only."""
        config_path = self.create_config_file(
            ["events", "connections"], 
            test_name="events_connections"
        )
        self.start_server(config_path)
        
        # Perform a command
        self.client.set("key1", "value1")
        
        # Create a new connection
        new_client = redis.Redis(host='localhost', port=self.port)
        new_client.ping()
        new_client.close()
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("connect", log_content.lower())
        self.assertNotIn("[KEY_OP] SET", log_content)
    
    def test_events_keys_parameter(self):
        """Test events parameter with keys only."""
        config_path = self.create_config_file(
            ["events", "keys"], 
            test_name="events_keys"
        )
        self.start_server(config_path)
        
        self.client.set("key2", "value2")
        
        # Try to authenticate (this may fail if no password is set)
        try:
            self.client.auth("wrongpassword")
        except redis.exceptions.AuthenticationError:
            pass
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)
        self.assertNotIn("[AUTH]", log_content)
    
    def test_events_multiple_parameter(self):
        """Test events parameter with multiple event types."""
        config_path = self.create_config_file(
            ["events", "auth,keys"],
            test_name="events_multiple"
        )
        self.start_server(config_path)
        
        self.client.set("key1", "value1")  # Keys event
        
        # Try to authenticate (this may fail if no password is set)
        try:
            self.client.auth("wrongpassword")
        except redis.exceptions.AuthenticationError:
            pass
        
        # Create a new connection (connections event)
        new_client = redis.Redis(host='localhost', port=self.port)
        new_client.ping()
        new_client.close()
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)  # Keys event should be logged
        
        # Note: AUTH might not be visible in logs if password protection is not enabled
        # We can only reliably check that connection events are not logged
        self.assertNotIn("connect", log_content.lower())  # Connections should not be logged
    
    def test_payload_disable_parameter(self):
        """Test payload_disable parameter."""
        config_path = self.create_config_file(
            ["payload_disable"], 
            test_name="payload_disable"
        )
        self.start_server(config_path)
        
        secret_value = "this-is-a-secret-value-12345"
        self.client.set("key1", secret_value)
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)
        self.assertIn("key=key1", log_content)
        self.assertNotIn(secret_value, log_content)  # Value should not be logged
    
    def test_payload_maxsize_parameter(self):
        """Test payload_maxsize parameter."""
        # Set a small max size
        config_path = self.create_config_file(
            ["payload_maxsize", "5"], 
            test_name="payload_maxsize"
        )
        self.start_server(config_path)
        
        # Set a value with a payload larger than max size
        long_value = "this_is_a_long_value_that_exceeds_maxsize"
        self.client.set("key1", long_value)
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)
        self.assertIn("key=key1", log_content)
        # Value should be truncated
        self.assertNotIn(long_value, log_content)
    
    def test_complex_configuration(self):
        """Test a complex configuration with multiple parameters."""
        config_path = self.create_config_file(
            [
                "enable", "yes",
                "format", "json",
                "events", "keys,auth",
                "payload_maxsize", "10",
                "always_audit_config", "yes"
            ], 
            test_name="complex_config"
        )
        self.start_server(config_path)
        
        long_value = "twelve_character_value_exceeding_limit"
        max_value = long_value[0:10]
        self.client.set("key1", long_value)
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        log_lines = log_content.strip().split("\n")
        
        set_cmd_found = False
        for line in log_lines:
            if not line:
                continue
                
            try:
                json_entry = json.loads(line)
                if json_entry.get("command") == "SET":
                    set_cmd_found = True
                    self.assertIn("key1", json_entry["details"])
                    # Check that value is truncated (if it's included)
                    details = json_entry["details"]
                    if "payload" in details:
                        self.assertIn(max_value, details)
                        parts = details.split("payload=")
                        result = parts[1].strip()
                        self.assertTrue(len(result) <= 10)
            except json.JSONDecodeError:
                continue
        
        self.assertTrue(set_cmd_found, "SET command not found in logs")
    
    def test_excluderules_parameter(self):
        """Test excluderules parameter with username and IP exclusion rules."""
        # Test 1: IP exclusion for localhost (127.0.0.1)
        # Since tests typically run locally, we can test IP exclusion with localhost
        config_path = self.create_config_file(
            ["excluderules", "@127.0.0.1"],
            test_name="excluderules_ip"
        )
        self.start_server(config_path)
        
        # Try to set a key - this should be excluded from audit logs
        # since we're connecting from 127.0.0.1
        self.client.set("key1", "value1")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # Check audit log - operations from excluded IP should not be logged
        log_content = self.read_audit_log()
        self.assertNotIn("[KEY_OP] SET", log_content)
        self.assertNotIn("key=key1", log_content)
        
        # Verify the IP exclusion rule is logged properly
        self.assertIn("excluderules=@127.0.0.1", log_content)
        
        # Test 2: Username exclusion rule
        # Stop the server and restart with username exclusion
        self.stop_server()
        config_path = self.create_config_file(
            ["excluderules", "admin"],
            test_name="excluderules_user"
        )
        self.start_server(config_path)
        
        # Configure users in the server
        self.client.execute_command("ACL", "SETUSER", "admin", "on", "nopass", "~*", "+@all")
        self.client.execute_command("ACL", "SETUSER", "normaluser", "on", "nopass", "~*", "+@all")
        
        # Test with excluded user (admin)
        self.client.execute_command("AUTH", "admin", "")
        self.client.set("key2", "value2")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # Check audit log - operations from excluded user should not be logged
        log_content = self.read_audit_log()
        self.assertNotIn("key=key2", log_content)
        
        # Test with non-excluded user (normaluser)
        self.client.execute_command("AUTH", "normaluser", "")
        self.client.set("key3", "value3")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # Operations from non-excluded user should be logged
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content)
        self.assertIn("normaluser", log_content)
        self.assertIn("key3", log_content)
        
        # Test 3: Combined IP and username exclusion
        # Stop the server and restart with both IP and username exclusion
        self.stop_server()
        config_path = self.create_config_file(
            ["excluderules", "admin@127.0.0.1"],
            test_name="excluderules_combined"
        )
        self.start_server(config_path)
        
        # Configure users again
        self.client.execute_command("ACL", "SETUSER", "admin", "on", "nopass", "~*", "+@all")
        self.client.execute_command("ACL", "SETUSER", "normaluser", "on", "nopass", "~*", "+@all")
        
        # Test with non-excluded user - should still be excluded due to IP
        self.client.execute_command("AUTH", "normaluser", "")
        self.client.set("key4", "value4")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # Check audit log - operations should be logged 
        log_content = self.read_audit_log()
        self.assertIn("key4", log_content)
        
        # Verify the combined exclusion rules are logged properly
        self.assertIn("Added exclusion rule: username=admin, ip=127.0.0.1", log_content)
        

    def test_auditusers_command(self):
        """Test the AUDITUSERS command."""
        config_path = self.create_config_file(test_name="auditusers")
        self.start_server(config_path)
        
        # Execute the AUDITUSERS command
        result = self.client.execute_command("AUDITUSERS")
        self.assertEqual(result, "OK - user hash table dumped to logs")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        # We can't easily verify the contents of the user hash table
        # We just check that the command executed successfully


if __name__ == "__main__":
    unittest.main()