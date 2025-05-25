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
    
    def test_002_set_protocol_tcp(self):
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

    def test_003_tcp_timeout_ms_config(self):
        """Test TCP timeout configuration"""
        # Test setting valid timeout values
        valid_timeouts = [100, 500, 1000, 5000, 30000]
        for timeout in valid_timeouts:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_timeout_ms", str(timeout))
            self.assertEqual(result, "OK", f"Failed to set tcp_timeout_ms to {timeout}")
            
            # Verify the value was set
            config_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.tcp_timeout_ms")
            self.assertEqual(len(config_result), 2, "CONFIG GET should return key-value pair")
            self.assertEqual(int(config_result[1]), timeout, f"tcp_timeout_ms not set to {timeout}")
        
        # Test invalid timeout values
        invalid_timeouts = [-1, -100, 0]
        for timeout in invalid_timeouts:
            with self.assertRaises(Exception) as context:
                self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_timeout_ms", str(timeout))
            # Should reject negative or zero values
            self.assertTrue("invalid" in str(context.exception).lower() or 
                        "error" in str(context.exception).lower() or
                        "fail" in str(context.exception).lower(),
                        f"Should reject invalid timeout {timeout}")

    def test_004_tcp_retry_interval_ms_config(self):
        """Test TCP retry interval configuration"""
        # Test setting valid retry interval values
        valid_intervals = [100, 500, 1000, 10000, 100000, 300000]
        for interval in valid_intervals:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_retry_interval_ms", str(interval))
            self.assertEqual(result, "OK", f"Failed to set tcp_retry_interval_ms to {interval}")
            
            # Verify the value was set
            config_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.tcp_retry_interval_ms")
            self.assertEqual(len(config_result), 2, "CONFIG GET should return key-value pair")
            self.assertEqual(int(config_result[1]), interval, f"tcp_retry_interval_ms not set to {interval}")
        
        # Test invalid retry interval values
        invalid_intervals = [-1, -500, 0]
        for interval in invalid_intervals:
            with self.assertRaises(Exception) as context:
                self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_retry_interval_ms", str(interval))
            self.assertTrue("invalid" in str(context.exception).lower() or 
                        "error" in str(context.exception).lower() or
                        "fail" in str(context.exception).lower(),
                        f"Should reject invalid retry interval {interval}")

    def test_005_tcp_max_retries_config(self):
        """Test TCP max retries configuration"""
        # Test setting valid max retries values
        valid_retries = [0, 1, 3, 5, 10, 100]
        for retries in valid_retries:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_max_retries", str(retries))
            self.assertEqual(result, "OK", f"Failed to set tcp_max_retries to {retries}")
            
            # Verify the value was set
            config_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.tcp_max_retries")
            self.assertEqual(len(config_result), 2, "CONFIG GET should return key-value pair")
            self.assertEqual(int(config_result[1]), retries, f"tcp_max_retries not set to {retries}")
        
        # Test invalid max retries values
        invalid_retries = [-1, -10]
        for retries in invalid_retries:
            with self.assertRaises(Exception) as context:
                self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_max_retries", str(retries))
            self.assertTrue("invalid" in str(context.exception).lower() or 
                        "error" in str(context.exception).lower() or
                        "fail" in str(context.exception).lower(),
                        f"Should reject invalid max retries {retries}")

    def test_006_tcp_reconnect_on_failure_config(self):
        """Test TCP reconnect on failure configuration"""
        # Test setting valid boolean values
        valid_values = [
            ("yes", "yes"), ("no", "no")
        ]
        
        for input_val, expected_val in valid_values:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_reconnect_on_failure", input_val)
            self.assertEqual(result, "OK", f"Failed to set tcp_reconnect_on_failure to {input_val}")
            
            # Verify the value was set
            config_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.tcp_reconnect_on_failure")
            self.assertEqual(len(config_result), 2, "CONFIG GET should return key-value pair")
            self.assertEqual((config_result[1]), expected_val, 
                            f"tcp_reconnect_on_failure not set correctly for input {input_val}")
        
        # Test invalid boolean values
        invalid_values = ["maybe", "2", "-1", "invalid"]
        for val in invalid_values:
            with self.assertRaises(Exception) as context:
                self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_reconnect_on_failure", val)
            self.assertTrue("invalid" in str(context.exception).lower() or 
                        "error" in str(context.exception).lower() or
                        "fail" in str(context.exception).lower(),
                        f"Should reject invalid boolean value {val}")

    def test_007_tcp_buffer_on_disconnect_config(self):
        """Test TCP buffer on disconnect configuration"""
        # Test setting valid boolean values
        valid_values = [
            ("yes", "yes"), ("no", "no")
        ]
        
        for input_val, expected_val in valid_values:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_buffer_on_disconnect", input_val)
            self.assertEqual(result, "OK", f"Failed to set tcp_buffer_on_disconnect to {input_val}")
            
            # Verify the value was set
            config_result = self.redis.execute_command("CONFIG", "GET", "AUDIT.tcp_buffer_on_disconnect")
            self.assertEqual(len(config_result), 2, "CONFIG GET should return key-value pair")
            self.assertEqual((config_result[1]), expected_val, 
                            f"tcp_buffer_on_disconnect not set correctly for input {input_val}")
        
        # Test invalid boolean values
        invalid_values = ["maybe", "2", "-1", "invalid"]
        for val in invalid_values:
            with self.assertRaises(Exception) as context:
                self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_buffer_on_disconnect", val)
            self.assertTrue("invalid" in str(context.exception).lower() or 
                        "error" in str(context.exception).lower() or
                        "fail" in str(context.exception).lower(),
                        f"Should reject invalid boolean value {val}")

    def test_008_tcp_config_integration(self):
        """Test TCP configuration integration and realistic scenarios"""
        import socket
        import threading
        import time
        from queue import Queue, Empty
        
        # Set up TCP configuration for testing
        self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_timeout_ms", "1000")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_retry_interval_ms", "100")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_max_retries", "3")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_reconnect_on_failure", "yes")
        self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_buffer_on_disconnect", "yes")
        
        # Verify all configurations were set
        configs_to_check = [
            ("AUDIT.tcp_timeout_ms", "1000"),
            ("AUDIT.tcp_retry_interval_ms", "100"),
            ("AUDIT.tcp_max_retries", "3"),
            ("AUDIT.tcp_reconnect_on_failure", "yes"),
            ("AUDIT.tcp_buffer_on_disconnect", "yes")
        ]
        
        for config_key, expected_value in configs_to_check:
            result = self.redis.execute_command("CONFIG", "GET", config_key)
            self.assertEqual(len(result), 2, f"CONFIG GET {config_key} should return key-value pair")
            self.assertEqual(result[1], expected_value, f"{config_key} not set to {expected_value}")
        
        # Test with disconnecting server to verify retry behavior
        received_data = Queue()
        server_sockets = []  # Keep track of all sockets for cleanup
        
        def unreliable_tcp_server(port, data_queue, disconnect_after=2):
            connection_count = 0
            
            while connection_count < 3:  # Allow multiple reconnections
                server_socket = None
                conn = None
                try:
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_sockets.append(server_socket)  # Track for cleanup
                    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server_socket.bind(('127.0.0.1', port))
                    server_socket.listen(1)
                    server_socket.settimeout(3.0)
                    
                    conn, addr = server_socket.accept()
                    connection_count += 1
                    data_queue.put(f"CONNECTION_{connection_count}")
                    
                    # Read some data then disconnect
                    messages_received = 0
                    while messages_received < disconnect_after:
                        try:
                            data = conn.recv(1024)
                            if not data:
                                break
                            data_queue.put(data.decode('utf-8', errors='ignore'))
                            messages_received += 1
                        except socket.timeout:
                            break
                    
                except Exception as e:
                    data_queue.put(f"SERVER_ERROR: {str(e)}")
                    break
                finally:
                    # Always close connection and server socket
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
                    if server_socket:
                        try:
                            server_socket.close()
                        except:
                            pass
                    
                    # Brief pause before next connection attempt
                    if connection_count < 3:
                        time.sleep(0.2)
        
        # Find an available port
        test_port = 20000
        while test_port < 20100:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.bind(('127.0.0.1', test_port))
                test_socket.close()
                break
            except OSError:
                test_port += 1
        
        # Start the unreliable server
        server_thread = threading.Thread(
            target=unreliable_tcp_server, 
            args=(test_port, received_data, 1)
        )
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(0.1)
        
        try:
            # Set TCP protocol
            tcp_config = f"tcp 127.0.0.1:{test_port}"
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.PROTOCOL", tcp_config)
            self.assertEqual(result, "OK", "Failed to set TCP protocol")
            
            # Generate multiple audit events to test reconnection
            for i in range(5):
                self.redis.set(f"retry_test_key_{i}", f"retry_test_value_{i}")
                time.sleep(0.1)
            
            # Give time for retries and reconnections
            time.sleep(2.0)
            
            # Check received data
            all_data = []
            connections_seen = 0
            
            try:
                while True:
                    data = received_data.get_nowait()
                    if data.startswith("CONNECTION_"):
                        connections_seen += 1
                    elif data.startswith("SERVER_ERROR:"):
                        # Log server errors but don't fail the test
                        print(f"Server error (expected during testing): {data}")
                    else:
                        all_data.append(data)
            except Empty:
                pass
            
            # We should see multiple connection attempts due to reconnect behavior
            self.assertGreater(connections_seen, 1, 
                            "Should have attempted multiple connections due to reconnect_on_failure")
            
            # Should have received some audit data
            combined_data = ''.join(all_data)
            self.assertGreater(len(combined_data), 0, 
                            "Should have received some audit data despite disconnections")
            
        finally:
            # Wait for server thread to complete
            if server_thread.is_alive():
                server_thread.join(timeout=3.0)
            
            # Ensure all server sockets are closed
            for sock in server_sockets:
                try:
                    sock.close()
                except:
                    pass
        
    def test_009_tcp_config_edge_cases(self):
        """Test edge cases and boundary values for TCP configuration"""
        
        # Test boundary values for timeout
        boundary_timeouts = [100, 60000]  
        for timeout in boundary_timeouts:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_timeout_ms", str(timeout))
            self.assertEqual(result, "OK", f"Failed to set boundary timeout {timeout}")
        
        # Test boundary values for retry interval
        boundary_intervals = [100, 300000] 
        for interval in boundary_intervals:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_retry_interval_ms", str(interval))
            self.assertEqual(result, "OK", f"Failed to set boundary retry interval {interval}")
        
        # Test boundary values for max retries
        boundary_retries = [0, 100]  
        for retries in boundary_retries:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_max_retries", str(retries))
            self.assertEqual(result, "OK", f"Failed to set boundary max retries {retries}")
        
        # Test case sensitivity for boolean values
        case_variations = ["YES", "Yes", "yeS", "yes", "NO", "No", "nO", "no"]
        for variation in case_variations:
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_reconnect_on_failure", variation)
            self.assertEqual(result, "OK", f"Failed to set case variation {variation}")
            result = self.redis.execute_command("CONFIG", "SET", "AUDIT.tcp_buffer_on_disconnect", variation)
            self.assertEqual(result, "OK", f"Failed to set numeric boolean {variation}")
        
        # Verify final state
        final_configs = self.redis.execute_command("CONFIG", "GET", "AUDIT.tcp_*")
        self.assertGreater(len(final_configs), 0, "Should return TCP configuration parameters")

if __name__ == "__main__":
    unittest.main(verbosity=2)