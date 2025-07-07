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
            #f.write(f"loadmodule {cls.module_path} protocol file {cls.log_file}\n")
            f.write(f"loadmodule {cls.module_path}\n")    
            f.write(f"audit.protocol file {cls.log_file}\n")
        
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
        result = self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "file "+new_log_file)
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
        result = self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "file "+ self.log_file)
        self.assertEqual(result, "OK", "Failed to set protocol to file")

        for fmt in formats:
            # Set the format
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.FORMAT", fmt)
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
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "config")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate different types of events
        self.redis.set("key1", "value1")  # Key operation - should NOT be logged
        self.redis.execute_command("CONFIG", "GET", "port")  # Config operation - should be logged
        self.redis.execute_command("INFO", "server")  # Other operation - should NOT be logged
        
        # Check log file
        log_lines = self._read_log_file()
        
        # Only CONFIG events should be logged
        self.assertTrue(any("CONFIG" in line for line in log_lines), 
                    "CONFIG event was not logged")
        self.assertFalse(any("KEY_OP" in line for line in log_lines), 
                        "KEY_OP event was logged but should not be")
        self.assertFalse(any("OTHER" in line for line in log_lines), 
                        "OTHER event was logged but should not be")
        
        # Test setting multiple events including other
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "config,keys,other")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate events again
        self.redis.set("key2", "value2")  # Key operation
        self.redis.execute_command("CONFIG", "GET", "port")  # Config operation
        self.redis.execute_command("INFO", "server")  # Other operation
        self.redis.execute_command("FLUSHDB")  # Other operation (administrative)
        
        # Check log file
        log_lines = self._read_log_file()
        
        # All three event types should be logged
        self.assertTrue(any("CONFIG" in line for line in log_lines), 
                    "CONFIG event was not logged")
        self.assertTrue(any("KEY_OP" in line for line in log_lines), 
                    "KEY_OP event was not logged")
        self.assertTrue(any("OTHER" in line for line in log_lines), 
                    "OTHER event was not logged")
        
        # Test setting only other events
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "other")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate different types of events
        self.redis.set("key3", "value3")  # Key operation - should NOT be logged
        self.redis.execute_command("CONFIG", "GET", "port")  # Config operation - should NOT be logged  
        self.redis.execute_command("INFO", "memory")  # Other operation - should be logged
        self.redis.execute_command("CLIENT", "LIST")  # Other operation - should be logged
        
        # Check log file
        log_lines = self._read_log_file()
        
        # Only OTHER events should be logged
        self.assertTrue(any("OTHER" in line for line in log_lines), 
                    "OTHER event was not logged")
        self.assertFalse(any("KEY_OP" in line for line in log_lines), 
                        "KEY_OP event was logged but should not be")
        self.assertFalse(any("CONFIG" in line for line in log_lines), 
                        "CONFIG event was logged but should not be")
        
        # Test disabling all events
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "none")
        
        # Clear log file
        self._clear_log_file()
        
        # Generate events
        self.redis.set("key4", "value4")
        self.redis.execute_command("CONFIG", "GET", "port")
        self.redis.execute_command("INFO", "server")
        
        # Check log file - should be empty
        log_lines = self._read_log_file()
        self.assertEqual(len(log_lines), 0, "Events were logged when all should be disabled")
        
        # Reset to all events for subsequent tests
        self.redis.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
    
    def test_005_payload_options(self):
        """Test payload logging options"""
        # Set a reasonable payload size
        self.redis.execute_command("CONFIG","SET","AUDIT.PAYLOAD_MAXSIZE", "10")
        
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
        self.redis.execute_command("CONFIG","SET","AUDIT.PAYLOAD_DISABLE", "yes")
        
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
        self.redis.execute_command("CONFIG","SET","AUDIT.PAYLOAD_DISABLE", "no")
    
    def test_006_get_config(self):
        """Test getting the current configuration"""
        self.redis.execute_command("CONFIG","SET","AUDIT.PAYLOAD_MAXSIZE", "1024")

        config = self.redis.execute_command("CONFIG GET AUDIT.*")
        
        # Check structure - Redis returns flat key-value pairs
        self.assertEqual(len(config), 32, "Config should have 32 items")
        
        # Convert flat array to dictionary (every two elements form a key-value pair)
        config_dict = {}
        for i in range(0, len(config), 2):
            key = config[i]
            value = config[i + 1]
            config_dict[key] = value
        
        # Debug output
        for key, value in config_dict.items():
            print(f"{key}: {value}")
        
        # Check for required configurations
        self.assertIn("audit.enabled", config_dict, "Missing audit.enabled config")
        self.assertIn("audit.always_audit_config", config_dict, "Missing audit.always_audit_config config")
        self.assertIn("audit.events", config_dict, "Missing audit.events config")
        self.assertIn("audit.format", config_dict, "Missing audit.format config")
        self.assertIn("audit.protocol", config_dict, "Missing audit.protocol config")
        self.assertIn("audit.payload_maxsize", config_dict, "Missing audit.payload_maxsize config")
        self.assertIn("audit.payload_disable", config_dict, "Missing audit.payload_disable config")
        self.assertIn("audit.auth_result_check_delay_ms", config_dict, "Missing audit.auth_result_check_delay_ms config")

        # Check protocol is set to file
        self.assertEqual(config_dict["audit.protocol"], "file "+self.log_file, 
                        "Protocol should be 'file audit.log")
        
        # Check format is json
        formats = ["json","csv","text"]
        self.assertIn(config_dict["audit.format"], formats, 
                        "Format should be 'json', 'csv' or 'text'")
        
        # Check events is set to all
        self.assertEqual(config_dict["audit.events"], "all", 
                        "Events should be 'all'")
        
        # Check payload settings
        self.assertEqual(config_dict["audit.payload_maxsize"], "1024",
                        "Payload maxsize should be '1024'")
        self.assertEqual(config_dict["audit.payload_disable"], "no",
                        "Payload disable should be 'no'")
        
        # Check audit is enabled
        yesno = ["yes","no"]
        self.assertIn(config_dict["audit.enabled"], yesno,
                        "Audit should be enabled")
        
        # Check always_audit_config is enabled
        self.assertIn(config_dict["audit.always_audit_config"], yesno,
                        "always_audit_config should be enabled")

    def test_007_set_protocol_syslog(self):
        """Test setting the audit protocol to syslog"""
        # Set the protocol to syslog with local0 facility
        result = self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "syslog local0")
        self.assertEqual(result, "OK", "Failed to set protocol to syslog")
        
        # Verify the protocol was set correctly
        protocol_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.PROTOCOL")
        self.assertIsInstance(protocol_result, list, "CONFIG GET should return a list")
        self.assertEqual(len(protocol_result), 2, "CONFIG GET should return key-value pair")
        self.assertEqual(protocol_result[0], "AUDIT.PROTOCOL", "Unexpected config key")
        self.assertEqual(protocol_result[1], "syslog local0", "Protocol not set correctly")
        
        # Write something to trigger an audit event
        self.redis.set("syslog_test_key", "syslog_test_value")
        
        # Note: For syslog testing, we can't easily verify the log content without 
        # access to system logs, but we can verify the command succeeded and 
        # didn't cause any errors
        
        # Test with different facility
        result = self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "syslog daemon")
        self.assertEqual(result, "OK", "Failed to set protocol to syslog with daemon facility")
        
        # Verify the facility change
        protocol_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.PROTOCOL")
        self.assertEqual(protocol_result[1], "syslog daemon", "Syslog facility not updated correctly")
        
        # Test invalid facility
        with self.assertRaises(Exception) as context:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "syslog invalid_facility")
        
        # The error message should mention invalid facility
        self.assertIn("Invalid syslog facility", str(context.exception))

    def test_008_set_protocol_tcp(self):
        """Test setting the audit protocol to TCP"""
        import socket
        import threading
        import time
        from queue import Queue, Empty
        
        # Create a simple TCP server to receive audit logs
        received_data = Queue()
        server_socket = None
        server_thread = None
        
        def tcp_server(port, data_queue):
            nonlocal server_socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server_socket.bind(('127.0.0.1', port))
                server_socket.listen(1)
                server_socket.settimeout(5.0)  # 5 second timeout
                
                conn, addr = server_socket.accept()
                conn.settimeout(2.0)
                
                # Read data from the connection
                while True:
                    try:
                        data = conn.recv(1024)
                        if not data:
                            break
                        data_queue.put(data.decode('utf-8', errors='ignore'))
                    except socket.timeout:
                        break
                    except Exception:
                        break
                
                conn.close()
            except Exception as e:
                data_queue.put(f"SERVER_ERROR: {str(e)}")
            finally:
                if server_socket:
                    server_socket.close()
        
        # Find an available port
        test_port = 19999
        while test_port < 20100:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.bind(('127.0.0.1', test_port))
                test_socket.close()
                break
            except OSError:
                test_port += 1
        
        # Start the TCP server
        server_thread = threading.Thread(target=tcp_server, args=(test_port, received_data))
        server_thread.daemon = True
        server_thread.start()
        
        # Give the server a moment to start
        time.sleep(0.1)
        
        try:
            # Set the protocol to TCP
            tcp_config = f"tcp 127.0.0.1:{test_port}"
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", tcp_config)
            self.assertEqual(result, "OK", "Failed to set protocol to TCP")
            
            # Verify the protocol was set correctly
            protocol_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.PROTOCOL")
            self.assertIsInstance(protocol_result, list, "CONFIG GET should return a list")
            self.assertEqual(len(protocol_result), 2, "CONFIG GET should return key-value pair")
            self.assertEqual(protocol_result[0], "AUDIT.PROTOCOL", "Unexpected config key")
            self.assertEqual(protocol_result[1], tcp_config, "TCP protocol not set correctly")
            
            # Write something to trigger an audit event
            self.redis.set("tcp_test_key", "tcp_test_value")
            self.redis.get("tcp_test_key")
            
            # Give some time for the audit log to be sent
            time.sleep(0.5)
            
            # Check if we received any data
            received_any_data = False
            all_received_data = []
            
            try:
                while True:
                    data = received_data.get_nowait()
                    if data.startswith("SERVER_ERROR:"):
                        self.fail(f"TCP server error: {data}")
                    all_received_data.append(data)
                    received_any_data = True
            except Empty:
                pass
            
            # We should have received some audit log data
            self.assertTrue(received_any_data, 
                        "No audit log data was received via TCP")
            
            # The received data should contain audit information
            combined_data = ''.join(all_received_data)
            self.assertIn("tcp_test_key", combined_data, 
                        "Audit log should contain the test key")
            
        finally:
            # Clean up
            if server_thread and server_thread.is_alive():
                server_thread.join(timeout=1.0)
        
        # Test invalid TCP format
        with self.assertRaises(Exception) as context:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "tcp invalid_format")
        
        self.assertIn("TCP format must be", str(context.exception))
        
        # Test invalid port
        with self.assertRaises(Exception) as context:
            self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", "tcp 127.0.0.1:99999")
        
        self.assertIn("Invalid port number", str(context.exception))

    def test_009_set_auth_delay(self):
        """Test setting the auth delay"""
        # Create a new log file path
        #new_log_file = os.path.join(self.temp_dir.name, "new_audit.log")
        new_log_file = os.path.join(self.temp_dir, "new_audit.log")
        
        # Set the protocol to file with the new path
        result = self.redis.execute_command("CONFIG", "SET", "AUDIT.auth_result_check_delay_ms", "100")
        self.assertEqual(result, "OK", "Failed to set auth result check delay")

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
            
if __name__ == "__main__":
    unittest.main(verbosity=2)