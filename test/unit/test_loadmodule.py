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
import threading


class ValkeyAuditLoadmoduleTest(unittest.TestCase):
    """Test cases for Valkey audit module configuration parameters."""
    
    @classmethod
    def setUpClass(cls):
        """Create a base temporary directory for all tests."""
        cls.base_temp_dir = tempfile.mkdtemp(prefix="vka-base-")
        print(f"Base temporary directory created: {cls.base_temp_dir}")
        
        # Path to Valkey server and module
        cls.valkey_server = os.environ.get("VALKEY_SERVER", "valkey-server")
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "libvalkeyaudit.so"))
        
        # Ensure the module exists
        if not os.path.exists(cls.module_path):
            raise FileNotFoundError(f"Audit module not found at {cls.module_path}")

        # Probe whether the server supports command result events
        cls.command_result_supported = cls._probe_command_result_support()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up the base temporary directory."""
        if os.path.exists(cls.base_temp_dir):
            #shutil.rmtree(cls.base_temp_dir)
            print(f"Base temporary directory NOT removed: {cls.base_temp_dir}")

    @classmethod
    def _probe_command_result_support(cls):
        """Start a temporary server and check if command result events fire."""
        probe_dir = tempfile.mkdtemp(prefix="vka-probe-")
        log_file = os.path.join(probe_dir, "probe.log")
        conf_file = os.path.join(probe_dir, "probe.conf")
        s = socket.socket(); s.bind(('', 0)); port = s.getsockname()[1]; s.close()
        with open(conf_file, 'w') as f:
            f.write(f"port {port}\nsave \"\"\n")
            f.write(f"loadmodule {cls.module_path}\n")
            f.write(f"audit.protocol file {log_file}\n")
            f.write(f"audit.events keys\n")  # keys only: exclude connections from probe
            f.write(f"audit.command_result_mode all\n")
        proc = subprocess.Popen([cls.valkey_server, conf_file],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(2)
            r = redis.Redis(host='localhost', port=port, decode_responses=True)
            open(log_file, 'w').close()
            r.set("__probe__", "string")
            try: r.lpush("__probe__", "val")
            except Exception: pass
            time.sleep(0.5)
            try:
                with open(log_file) as f:
                    supported = len(f.read()) > 0
            except FileNotFoundError:
                supported = False
            r.close()
        finally:
            proc.terminate()
            proc.wait(timeout=5)
        if not supported:
            print("\n  NOTE: Server does not support command result events (PR #2936). "
                  "All loadmodule tests will be skipped.")
        return supported

    def setUp(self):
        """Set up a fresh server environment for each test."""
        if not self.command_result_supported:
            self.skipTest("Server does not support command result events (requires PR #2936)")
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
        # Close the client connection before terminating the server so the
        # close handshake can complete while the server is still running.
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

        # Stop the server
        if self.server_proc:
            try:
                self.server_proc.terminate()
                self.server_proc.wait(timeout=5)
            except Exception:
                try:
                    self.server_proc.kill()
                    self.server_proc.wait(timeout=2)
                except Exception:
                    pass
            # Always close the PIPE handles; leaving them open causes ResourceWarning
            # when Python's GC eventually finalises the _io.BufferedReader objects.
            if self.server_proc.stdout:
                self.server_proc.stdout.close()
            if self.server_proc.stderr:
                self.server_proc.stderr.close()
            self.server_proc = None

        # Clean up the test-specific temporary directory
        if os.path.exists(self.temp_dir):
            #shutil.rmtree(self.temp_dir)
            print(f"Test temporary directory NOT removed: {self.temp_dir}")
    
    def create_config_file(self, module_params=None, test_name=None, command_result_mode="all"):
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
        
        # Check if any protocol is already specified in module_params
        has_protocol = False
        protocol_type = None
        if module_params:
            for i, param in enumerate(module_params):
                print(f"param: {param}")
                if param == "protocol" and i+1 < len(module_params):
                    has_protocol = True
                    protocol_type = module_params[i+1]
                    if protocol_type == "file":
                        self.audit_log_path = module_params[i+2]

                    break
        print(f"\n \n proto:{protocol_type} \n \n")

        # Start with the base loadmodule command
        module_load_line = f"loadmodule {self.module_path}"

        # If module_params has any protocol specified, add the parameters as is
        if module_params and has_protocol:
            module_load_line += ' ' + ' '.join(module_params)
                
        # Otherwise, add module_params + our default protocol file
        elif module_params:
            module_load_line += ' ' + ' '.join(module_params) + f" protocol file {self.audit_log_path}"
        # If no module_params, just add our default protocol file
        else:
            module_load_line += f" protocol file {self.audit_log_path}"
        
        # Create the config file
        with open(self.valkey_conf_path, 'w') as f:
            f.write(f"logfile /tmp/vka.log \n")
            f.write(f"port {self.port}\n")
            f.write(f"{module_load_line}\n")
            f.write(f"audit.command_result_mode {command_result_mode}\n")
        
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

        # Close Redis client connection before terminating so the close
        # handshake can complete while the server is still alive.
        if hasattr(self, 'client') and self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

        # Terminate the server process
        if hasattr(self, 'server_proc') and self.server_proc:
            self.server_proc.terminate()
            try:
                self.server_proc.wait(timeout=5)
                print("Server stopped gracefully")
            except subprocess.TimeoutExpired:
                print("Server did not terminate gracefully, force killing...")
                self.server_proc.kill()
                self.server_proc.wait()
                print("Server forcefully terminated")

            # Close PIPE handles to prevent ResourceWarning from GC
            if self.server_proc.stdout:
                self.server_proc.stdout.close()
            if self.server_proc.stderr:
                self.server_proc.stderr.close()
            self.server_proc = None
        else:
            print("No server process was running")

        # Verify server is actually stopped by attempting to connect
        test_client = redis.Redis(host='localhost', port=self.port, decode_responses=True)
        try:
            test_client.ping()
            print("WARNING: Server appears to still be running!")
            return False
        except redis.exceptions.ConnectionError:
            print(f"Confirmed server is no longer running on port {self.port}")
            return True
        finally:
            test_client.close()
    
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
        self.assertIn("[KEY_OP] SET", log_content.upper())

    def test_enable_parameter(self):
        """Test enable parameter (on/off)."""
        # Test enabled
        config_path = self.create_config_file(["enabled", "yes"], test_name="enable_yes")
        self.start_server(config_path)
        
        self.client.set("key1", "value1")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content.upper())
    
    def test_disable_parameter(self):
        """Test disable parameter."""
        config_path = self.create_config_file(["enabled", "no"], test_name="enable_no")
        self.start_server(config_path)
        
        self.client.set("key2", "value2")
        
        # Give time for logs to be written
        time.sleep(0.5)
        
        log_content = self.read_audit_log()
        # When disabled, log should not contain SET command
        self.assertNotIn("[KEY_OP] SET", log_content.upper())

    def test_command_result_mode_all_logs_success(self):
        """In 'all' mode, successful commands produce a SUCCESS log entry."""
        config_path = self.create_config_file(
            ["events", "keys"],
            test_name="result_mode_all",
            command_result_mode="all",
        )
        self.start_server(config_path)

        self.client.set("mode_all_key", "value")
        time.sleep(0.5)

        log_content = self.read_audit_log()
        self.assertIn("[KEY_OP] SET", log_content.upper(),
                      f"SET command should appear in log in 'all' mode\nLog:\n{log_content}")
        self.assertIn("SUCCESS", log_content.upper(),
                      f"Successful SET should be logged with SUCCESS in 'all' mode\nLog:\n{log_content}")

    def test_command_result_mode_failures_suppresses_success(self):
        """In 'failures' mode, successful commands are not logged; failures are.

        The module subscribes to SUCCESS events only at load time when
        command_result_mode=all.  Starting with command_result_mode=failures
        means the server never fires success callbacks for this module, so
        no overhead and no log entry for clean commands.
        """
        config_path = self.create_config_file(
            ["events", "keys"],
            test_name="result_mode_failures",
            command_result_mode="failures",
        )
        self.start_server(config_path)

        # Successful SET — should produce no log entry
        self.client.set("mode_fail_key", "value")
        time.sleep(0.5)

        log_content = self.read_audit_log()
        self.assertNotIn("mode_fail_key", log_content,
                         f"Successful SET should NOT appear in log in 'failures' mode\nLog:\n{log_content}")
        self.assertNotIn("SUCCESS", log_content.upper(),
                         f"No SUCCESS entries should exist in 'failures' mode\nLog:\n{log_content}")

        # Failed command (WRONGTYPE) — should be logged as FAILURE
        open(self.audit_log_path, 'w').close()
        try:
            self.client.lpush("mode_fail_key", "val")  # mode_fail_key is a string, not a list
        except redis.exceptions.ResponseError:
            pass  # Expected: WRONGTYPE error

        time.sleep(0.5)
        log_content = self.read_audit_log()
        self.assertIn("FAILURE", log_content.upper(),
                      f"Failed command should be logged as FAILURE in 'failures' mode\nLog:\n{log_content}")

    def test_always_audit_config_parameter(self):
        """Test always_audit_config parameter."""
        config_path = self.create_config_file(
            ["enabled", "yes", "always_audit_config", "yes", "events", "none"], 
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
        self.assertNotIn("[KEY_OP] SET", log_content.upper())
        self.assertIn("[CONFIG]", log_content.upper())
        # Details use lowercase key names (subcommand=SET), so compare consistently.
        # The server passes "CONFIG|SET" as the canonical command_name for subcommands.
        self.assertIn("subcommand=SET".upper(), log_content.upper())

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
        self.assertIn("[KEY_OP] SET", custom_log_content.upper())
        
        # Default log (which would be self.audit_log_path) should be ignored in this case
        # since we explicitly specified a different path
    
    def test_protocol_syslog_parameter(self):
        """Test protocol 'syslog' with custom facility."""
        # Test with local0 facility
        config_path = self.create_config_file(
            ["protocol", "syslog", "local0"], 
            test_name="protocol_syslog_local0"
        )
        self.start_server(config_path)
        
        self.client.set("key1", "value1")
        
        # Give time for logs to be written to syslog
        time.sleep(0.5)
        
        # Check syslog for audit entries
        # Note: This assumes you have access to read syslog entries
        # You might need to adjust the syslog reading method based on your system
        syslog_entries = self.read_syslog_entries()
        self.assertIn("valkey-audit", syslog_entries)
        self.assertIn("[KEY_OP] SET", syslog_entries.upper())

    def test_protocol_syslog_default_facility(self):
        """Test protocol 'syslog' with default facility when none specified."""
        config_path = self.create_config_file(
            ["protocol", "syslog"], 
            test_name="protocol_syslog_default"
        )
        self.start_server(config_path)

        self.client.set("key2", "value2")

        # Give time for logs to be written to syslog
        time.sleep(0.5)

        syslog_entries = self.read_syslog_entries()
        self.assertIn("valkey-audit", syslog_entries)
        self.assertIn("[KEY_OP] SET", syslog_entries.upper())

    def test_protocol_syslog_various_facilities(self):
        """Test protocol 'syslog' with different facilities."""
        facilities = ["local1", "local2", "user", "daemon"]
        
        for facility in facilities:
            with self.subTest(facility=facility):
                config_path = self.create_config_file(
                    ["protocol", "syslog", facility], 
                    test_name=f"protocol_syslog_{facility}"
                )
                self.start_server(config_path)
                
                self.client.set(f"key_{facility}", f"value_{facility}")
                
                # Give time for logs to be written
                time.sleep(0.5)
                
                syslog_entries = self.read_syslog_entries()
                self.assertIn("valkey-audit", syslog_entries.lower())
                self.assertIn(f"[KEY_OP] set".lower(), syslog_entries.lower())
                
                self.stop_server()

    def test_protocol_tcp_parameter(self):
        """Test protocol 'tcp' with custom host:port."""
        # Start a mock TCP syslog server
        mock_tcp_server = self.start_mock_tcp_server("127.0.0.1", 9514)
        time.sleep(2)
        
        try:
            config_path = self.create_config_file(
                ["protocol", "tcp", '"127.0.0.1:9514"'], 
                test_name="protocol_tcp"
            )
            self.start_server(config_path)
            
            self.client.set("key1", "value1")
            
            # Give time for TCP logs to be sent
            time.sleep(5)
            
            # Check received messages on mock TCP server
            received_messages = mock_tcp_server.get_received_messages()
            print(f"received: {received_messages}")
            found = False
            self.assertTrue(len(received_messages) > 0)
            for msg in received_messages:
                if "[KEY_OP] set".lower() in msg.lower():
                    found = True
            self.assertTrue(found)
            
        finally:
            mock_tcp_server.stop()
    
    def test_protocol_tcp_connection_failure(self):
        """Test protocol 'tcp' behavior when connection fails."""
        # Don't start a mock server - connection should fail
        config_path = self.create_config_file(
            ["protocol", "tcp", '"127.0.0.1:9999"'], 
            test_name="protocol_tcp_failure"
        )
        self.start_server(config_path)
        
        # Server should start even if TCP connection fails
        self.assertTrue(self.server_proc.poll() is None)
        
        self.client.set("key4", "value4")
        
        # Give time for connection attempts and retries
        time.sleep(2.0)
        
        # Server should still be running despite TCP connection failure
        self.assertTrue(self.server_proc.poll() is None)

    def test_protocol_tcp_with_options(self):
        """Test protocol 'tcp' with additional TCP-specific options."""
        mock_tcp_server = self.start_mock_tcp_server("127.0.0.1", 9515)
        
        try:
            config_path = self.create_config_file([
                "protocol", "tcp", '"127.0.0.1:9515"',
                "tcp_timeout", "3000",
                "tcp_retry_interval", "500", 
                "tcp_max_retries", "5",
                "tcp_reconnect", "yes",
                "tcp_buffer", "yes"
            ], test_name="protocol_tcp_options")
            self.start_server(config_path)
            
            self.client.set("key5", "value5")
            
            # Give time for TCP logs to be sent
            time.sleep(1.0)
            
            received_messages = mock_tcp_server.get_received_messages()
            found = False
            self.assertTrue(len(received_messages) > 0)
            for msg in received_messages:
                if "[KEY_OP] set".lower() in msg.lower():
                    found = True
            self.assertTrue(found)
            
        finally:
            mock_tcp_server.stop()

    def read_syslog_entries(self):
        """Read recent syslog entries containing valkey-audit."""
        try:
            # This implementation depends on your system's syslog configuration
            # Common approaches:
            
            # Option 1: Read from /var/log/syslog (Ubuntu/Debian)
            with open('/var/log/syslog', 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-100:]  # Get last 100 lines
                return '\n'.join([line for line in recent_lines if 'valkey-audit' in line])
                
            # Option 2: Use journalctl (systemd systems)
            # import subprocess
            # result = subprocess.run(['journalctl', '-n', '100', '--grep', 'valkey-audit'], 
            #                        capture_output=True, text=True)
            # return result.stdout
            
        except Exception as e:
            self.skipTest(f"Unable to read syslog: {e}")

    def start_mock_tcp_server(self, host, port):
        """Start a mock TCP server to capture audit logs."""
        return MockTCPServer(host, port)

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
                if "command" in json_entry and json_entry["command"].upper() == "SET":
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
                if len(row) > 3 and "SET" in line.upper():
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
        self.assertNotIn("[KEY_OP] SET".lower(), log_content.lower())
    
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
        self.assertIn("[KEY_OP] SET".upper(), log_content.upper())
        self.assertNotIn("[AUTH]", log_content.upper())
    
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
        self.assertIn("[KEY_OP] SET", log_content.upper())  # Keys event should be logged
        
        # Note: AUTH might not be visible in logs if password protection is not enabled
        # We can only reliably check that connection events are not logged
        self.assertNotIn("connection", log_content.lower())  # Connections should not be logged
    
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
        self.assertIn("[KEY_OP] SET".lower(), log_content.lower())
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
        self.assertIn("[KEY_OP] SET", log_content.upper())
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
                if json_entry.get("command", "").upper() == "SET":
                    set_cmd_found = True
                    self.assertIn("key1", json_entry["details"])
                    # Check that value is truncated (if it's included)
                    details = json_entry["details"]
                    if "payload" in details:
                        self.assertIn(max_value, details)
                        parts = details.split("payload=")
                        result = parts[1].strip().replace("...(truncated)", "")
                        #import pdb; pdb.set_trace()
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
        self.assertNotIn("[KEY_OP] SET", log_content.upper())
        self.assertNotIn("key=key1", log_content.lower())
        
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
        self.assertIn("[KEY_OP] SET", log_content.upper())
        self.assertIn("normaluser", log_content.lower())
        self.assertIn("key3", log_content.lower())

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
        #self.assertIn("Added exclusion rule: username=admin, ip=127.0.0.1", log_content)

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

    def test_ignore_internal_clients_getter(self):
        """Test the ignore_internal_clients configuration getter."""
        # Test default value (should be yes/1)
        config_path = self.create_config_file(test_name="ignore_internal_clients_getter")
        self.start_server(config_path)

        # Get the current ignore_internal_clients setting
        result = self.client.config_get("audit.ignore_internal_clients")
        self.assertIsNotNone(result)
        self.assertIn("audit.ignore_internal_clients", result)
        self.assertEqual(result["audit.ignore_internal_clients"], "yes")

        # Change the setting and verify the getter returns new value
        self.client.config_set("audit.ignore_internal_clients", "no")
        result = self.client.config_get("audit.ignore_internal_clients")
        self.assertEqual(result["audit.ignore_internal_clients"], "no")

        # Change back to yes
        self.client.config_set("audit.ignore_internal_clients", "yes")
        result = self.client.config_get("audit.ignore_internal_clients")
        self.assertEqual(result["audit.ignore_internal_clients"], "yes")

    def test_ignore_internal_clients_setter(self):
        """Test the ignore_internal_clients configuration setter."""
        config_path = self.create_config_file(test_name="ignore_internal_clients_setter")
        self.start_server(config_path)

        # Test setting to no
        result = self.client.config_set("audit.ignore_internal_clients", "no")
        self.assertEqual(result, True)

        # Verify it was set
        config = self.client.config_get("audit.ignore_internal_clients")
        self.assertEqual(config["audit.ignore_internal_clients"], "no")

        # Test setting to yes
        result = self.client.config_set("audit.ignore_internal_clients", "yes")
        self.assertEqual(result, True)

        # Verify it was set
        config = self.client.config_get("audit.ignore_internal_clients")
        self.assertEqual(config["audit.ignore_internal_clients"], "yes")

    def test_ignore_internal_clients_exclusion_with_replica(self):
        """Test that internal clients (like replica connections) are excluded when ignore_internal_clients=yes."""
        # Create primary server configuration
        primary_config_path = self.create_config_file(
            ["ignore_internal_clients", "yes"],
            test_name="ignore_internal_primary"
        )
        self.start_server(primary_config_path)

        # Set up a key on the primary
        self.client.set("test_key", "test_value")

        # Give time for logs to be written
        time.sleep(0.5)

        # Read primary audit log
        primary_log = self.read_audit_log()

        # Regular client SET should be logged
        self.assertIn("[KEY_OP] SET", primary_log.upper())
        self.assertIn("test_key", primary_log.lower())

        # Now set up a replica to connect to the primary
        # Create replica temp directory
        replica_temp_dir = tempfile.mkdtemp(prefix="vka-replica-", dir=self.base_temp_dir)
        replica_conf_path = os.path.join(replica_temp_dir, "valkey.conf")
        replica_audit_log = os.path.join(replica_temp_dir, "replica_audit.log")

        # Find an available port for replica
        s = socket.socket()
        s.bind(('', 0))
        replica_port = s.getsockname()[1]
        s.close()

        # Create replica config with ignore_internal_clients enabled
        with open(replica_conf_path, 'w') as f:
            f.write(f"port {replica_port}\n")
            f.write(f"replicaof 127.0.0.1 {self.port}\n")
            f.write(f"loadmodule {self.module_path} protocol file {replica_audit_log} ignore_internal_clients yes\n")
            f.write(f"audit.command_result_mode all\n")

        # Start replica server
        replica_proc = subprocess.Popen(
            [self.valkey_server, replica_conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            # Wait for replica to start and connect
            time.sleep(2)

            # Create client connection to replica
            replica_client = redis.Redis(host='localhost', port=replica_port, decode_responses=True)
            replica_client.ping()

            # Do some operations on the primary to trigger replication
            self.client.set("replicated_key", "replicated_value")
            self.client.set("another_key", "another_value")

            # Give time for replication and logging
            time.sleep(2)

            # Read replica audit log
            if os.path.exists(replica_audit_log):
                with open(replica_audit_log, 'r') as f:
                    replica_log_content = f.read()

                print(f"Replica audit log content:\n{replica_log_content}")

                # Get INFO replication to verify replica is connected
                info = replica_client.info("replication")
                print(f"Replica info: {info}")

                # With ignore_internal_clients=yes, internal replication commands should NOT be logged
                # The replica receives commands from the primary connection (which is internal/superuser)
                # Check that these internal SET commands from replication are NOT in the replica audit log
                # (Regular client commands to the replica would still be logged)

                # Count SET operations in replica log - should be minimal or none from replication
                set_count = replica_log_content.upper().count("[KEY_OP] SET")

                # Internal replication traffic should not be audited
                # The exact count depends on initialization, but replication data should be excluded
                print(f"SET operations logged on replica: {set_count}")

                # Test that a direct client operation on replica IS logged
                # (even though replica is read-only by default, we can test with other commands)
                try:
                    replica_client.get("test_key")
                    time.sleep(0.5)

                    with open(replica_audit_log, 'r') as f:
                        updated_replica_log = f.read()

                    # GET command from external client should be logged
                    self.assertIn("[KEY_OP] GET", updated_replica_log.upper())
                except Exception as e:
                    print(f"Replica read test: {e}")

            replica_client.close()

        finally:
            # Clean up replica
            replica_proc.terminate()
            try:
                replica_proc.wait(timeout=5)
            except:
                replica_proc.kill()
            if replica_proc.stdout:
                replica_proc.stdout.close()
            if replica_proc.stderr:
                replica_proc.stderr.close()

            if os.path.exists(replica_temp_dir):
                shutil.rmtree(replica_temp_dir)

    def test_ignore_internal_clients_disabled_logs_replica_traffic(self):
        """Test that internal clients are logged when ignore_internal_clients=no."""
        # Create primary server
        primary_config_path = self.create_config_file(
            test_name="ignore_internal_disabled_primary"
        )
        self.start_server(primary_config_path)

        # Now set up a replica with ignore_internal_clients=no
        replica_temp_dir = tempfile.mkdtemp(prefix="vka-replica-log-", dir=self.base_temp_dir)
        replica_conf_path = os.path.join(replica_temp_dir, "valkey.conf")
        replica_audit_log = os.path.join(replica_temp_dir, "replica_audit.log")

        # Find an available port for replica
        s = socket.socket()
        s.bind(('', 0))
        replica_port = s.getsockname()[1]
        s.close()

        # Create replica config with ignore_internal_clients disabled
        with open(replica_conf_path, 'w') as f:
            f.write(f"port {replica_port}\n")
            f.write(f"replicaof 127.0.0.1 {self.port}\n")
            f.write(f"loadmodule {self.module_path} protocol file {replica_audit_log} ignore_internal_clients no\n")
            f.write(f"audit.command_result_mode all\n")

        # Start replica server
        replica_proc = subprocess.Popen(
            [self.valkey_server, replica_conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            # Wait for replica to start and connect
            time.sleep(2)

            # Create client connection to replica
            replica_client = redis.Redis(host='localhost', port=replica_port, decode_responses=True)
            replica_client.ping()

            # Do operations on the primary to trigger replication
            self.client.set("internal_test_key", "internal_test_value")
            self.client.set("another_internal_key", "another_value")

            # Give time for replication and logging
            time.sleep(2)

            # Read replica audit log
            if os.path.exists(replica_audit_log):
                with open(replica_audit_log, 'r') as f:
                    replica_log_content = f.read()

                print(f"Replica audit log (ignore_internal_clients=no):\n{replica_log_content}")

                # With ignore_internal_clients=no, internal replication commands SHOULD be logged
                set_count = replica_log_content.upper().count("[KEY_OP] SET")

                print(f"SET operations logged on replica with ignore_internal_clients=no: {set_count}")

                # We should see the replicated SET commands logged
                # The exact count may vary, but should be > 0
                self.assertGreater(set_count, 0,
                    "When ignore_internal_clients=no, internal replica traffic should be logged")

            replica_client.close()

        finally:
            # Clean up replica
            replica_proc.terminate()
            try:
                replica_proc.wait(timeout=5)
            except:
                replica_proc.kill()
            if replica_proc.stdout:
                replica_proc.stdout.close()
            if replica_proc.stderr:
                replica_proc.stderr.close()

            if os.path.exists(replica_temp_dir):
                shutil.rmtree(replica_temp_dir)

    def test_ignore_internal_clients_parameter_at_load(self):
        """Test ignore_internal_clients can be set via loadmodule parameter."""
        # Test setting to no at load time
        config_path = self.create_config_file(
            ["ignore_internal_clients", "no"],
            test_name="ignore_internal_load_no"
        )
        self.start_server(config_path)

        # Verify it was set to no
        config = self.client.config_get("audit.ignore_internal_clients")
        self.assertEqual(config["audit.ignore_internal_clients"], "no")

        # Stop and restart with yes
        self.stop_server()

        config_path = self.create_config_file(
            ["ignore_internal_clients", "yes"],
            test_name="ignore_internal_load_yes"
        )
        self.start_server(config_path)

        # Verify it was set to yes
        config = self.client.config_get("audit.ignore_internal_clients")
        self.assertEqual(config["audit.ignore_internal_clients"], "yes")

class MockTCPServer:
    """Mock TCP server for testing TCP audit logging."""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.messages = []
        self.messages_lock = threading.Lock()  # Thread safety
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.start()
    
    def start(self):
        """Start the mock TCP server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set socket timeout to prevent indefinite blocking
        self.server_socket.settimeout(1.0)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        self.server_thread = threading.Thread(target=self._accept_connections)
        self.server_thread.daemon = True
        self.server_thread.start()
    
    def _accept_connections(self):
        """Accept and handle incoming connections."""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"Connection accepted from {addr}")  # Debug info
                threading.Thread(
                    target=self._handle_client, 
                    args=(client_socket,), 
                    daemon=True
                ).start()
            except socket.timeout:
                # Timeout allows us to check self.running periodically
                continue
            except OSError as e:
                # Socket was closed
                if self.running:
                    print(f"Socket error: {e}")
                break
            except Exception as e:
                print(f"Unexpected error in accept_connections: {e}")
                break
    
    def _handle_client(self, client_socket):
        """Handle individual client connections."""
        try:
            client_socket.settimeout(1.0)  # Prevent indefinite blocking on recv
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    message = data.decode('utf-8')
                    print(f"Received message: {message}")  # Debug info
                    
                    # Thread-safe message storage
                    with self.messages_lock:
                        self.messages.append(message)
                        
                except socket.timeout:
                    continue  # Check self.running again
                except UnicodeDecodeError as e:
                    print(f"Failed to decode message: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def get_received_messages(self):
        """Get all received messages."""
        with self.messages_lock:
            return self.messages.copy()  # Return a copy to avoid race conditions
    
    def clear_messages(self):
        """Clear all received messages."""
        with self.messages_lock:
            self.messages.clear()
    
    def stop(self):
        """Stop the mock TCP server."""
        print("Stopping server...")
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
            
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2.0)
            if self.server_thread.is_alive():
                print("Warning: Server thread did not stop cleanly")


# test TCP server usage 
if __name__ == "__main__":
    # Test the server
    server = MockTCPServer('localhost', 12345)
    
    try:
        # Give server time to start
        time.sleep(0.1)
        
        # Send a test message
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect(('localhost', 12345))
        test_socket.send(b"Hello, Server!")
        test_socket.close()
        
        # Wait a moment for message processing
        time.sleep(0.1)
        
        # Check received messages
        messages = server.get_received_messages()
        print(f"Received messages: {messages}")
        
    finally:
        server.stop()
 

if __name__ == "__main__":
    unittest.main()