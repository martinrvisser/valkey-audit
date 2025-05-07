#!/usr/bin/env python3
import unittest
import redis
import os
import tempfile
import time
import subprocess
import re
from pathlib import Path
import uuid

class ValkeyAuditExcludedUsersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary directory for test files
        cls.temp_dir = tempfile.mkdtemp(prefix="vka-ex-")
        print(f"Temporary directory created: {cls.temp_dir}")
        cls.log_file = os.path.join(cls.temp_dir, "audit.log")

        # Path to Valkey server and module
        cls.valkey_server = os.environ.get("VALKEY_SERVER", "valkey-server")
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH", "./audit.so")
        
        # Start Valkey server with the audit module and ACL enabled
        cls._start_valkey_server()
        
        # Connect to the server as admin
        cls.redis_admin = redis.Redis(host='localhost', port=cls.port, password="defaultpass", decode_responses=True)
        
        # Wait for server to be ready
        max_retries = 10
        for i in range(max_retries):
            try:
                cls.redis_admin.ping()
                break
            except redis.exceptions.ConnectionError:
                if i == max_retries - 1:
                    raise
                time.sleep(0.5)
                
        # Create test users
        cls._create_test_users()
    
    @classmethod
    def tearDownClass(cls):
        # Stop the server
        cls._stop_valkey_server()
        
        # Clean up temporary directory
        #cls.temp_dir.cleanup()
    
    @classmethod
    def _start_valkey_server(cls):
        """Start a Valkey server instance for testing with ACL enabled"""
        # Find an available port
        import socket
        s = socket.socket()
        s.bind(('', 0))
        cls.port = s.getsockname()[1]
        s.close()
        
        # Create configuration file with ACL enabled
        cls.conf_file = os.path.join(cls.temp_dir, "valkey.conf")
        with open(cls.conf_file, 'w') as f:
            f.write(f"port {cls.port}\n")
            f.write("aclfile /tmp/valkey-acl-test.acl\n")  # ACL enabled
            f.write("logfile /tmp/valkeytest.log\n")
            f.write(f"loadmodule {cls.module_path}\n")    
            f.write(f"audit.protocol file {cls.log_file}\n")
  
        
        # Create ACL file with default user
        with open("/tmp/valkey-acl-test.acl", 'w') as f:
            f.write("user default on +@all ~* >defaultpass\n")
        
        # Start the server
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
        
        # Remove the temporary ACL file
        try:
            os.remove("/tmp/valkey-acl-test.acl")
        except:
            pass
    
    @classmethod
    def _create_test_users(cls):
        """Create test users for excluded users testing"""
        # Generate unique usernames to avoid conflicts
        cls.user1 = f"testuser1_{str(uuid.uuid4())[:8]}"
        cls.user2 = f"testuser2_{str(uuid.uuid4())[:8]}"
        
        # Create users with full permissions
        cls.redis_admin.execute_command("ACL", "SETUSER", cls.user1, "on", "+@all", "~*", ">pass1")
        cls.redis_admin.execute_command("ACL", "SETUSER", cls.user2, "on", "+@all", "~*", ">pass2")
        
        # Create connections for each user
        cls.redis_user1 = redis.Redis(
            host='localhost', 
            port=cls.port, 
            username=cls.user1, 
            password="pass1", 
            decode_responses=True
        )
        
        cls.redis_user2 = redis.Redis(
            host='localhost', 
            port=cls.port, 
            username=cls.user2, 
            password="pass2", 
            decode_responses=True
        )
    
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
    
    def test_001_exclude_single_user(self):
        """Test excluding a single user from audit"""
        # Set format to text for easier parsing
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Enable all event types
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        # Exclude user1 from audit (username only rule)
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", self.user1)
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands as both users
        self.redis_user1.set("exclude_test_key1", "value1")
        self.redis_user2.set("exclude_test_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check user1's command should NOT be logged
        user1_logged = any(f"exclude_test_key1" in line for line in log_lines)
        self.assertFalse(user1_logged, f"Excluded user {self.user1} was logged")
        
        # Check user2's command should be logged
        user2_logged = any(f"exclude_test_key2" in line for line in log_lines)
        self.assertTrue(user2_logged, f"Non-excluded user {self.user2} was not logged")

    def test_002_exclude_by_ip_address(self):
        """Test excluding clients by IP address from audit"""
        # Set format to text for easier parsing
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Enable all event types
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        # Exclude localhost IP address
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", "@127.0.0.1")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands from localhost (all test clients)
        self.redis_user1.set("ip_exclude_test_key1", "value1")
        self.redis_user2.set("ip_exclude_test_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check neither command should be logged since both come from localhost
        user1_logged = any(f"ip_exclude_test_key1" in line for line in log_lines)
        user2_logged = any(f"ip_exclude_test_key2" in line for line in log_lines)
        
        self.assertFalse(user1_logged, f"Command from excluded IP was logged")
        self.assertFalse(user2_logged, f"Command from excluded IP was logged")

    def test_003_exclude_specific_user_from_specific_ip(self):
        """Test excluding specific user from specific IP address"""
        # Set format to text for easier parsing
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Enable all event types
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        # Exclude user1 only when connecting from localhost
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", f"{self.user1}@127.0.0.1")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands as both users
        self.redis_user1.set("specific_exclude_key1", "value1")
        self.redis_user2.set("specific_exclude_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check user1's command should NOT be logged (excluded by username@ip)
        user1_logged = any(f"specific_exclude_key1" in line for line in log_lines)
        self.assertFalse(user1_logged, f"User excluded by username@ip was logged")
        
        # Check user2's command should be logged
        user2_logged = any(f"specific_exclude_key2" in line for line in log_lines)
        self.assertTrue(user2_logged, f"Non-excluded user was not logged")

    def test_004_exclude_multiple_rules(self):
        """Test excluding with multiple rules (username, IP, and combo)"""
        # Exclude with multiple rules:
        # 1. user1 from any IP
        # 2. Any user from 192.168.1.1
        # 3. user2 specifically from 127.0.0.1
        excluded_rules = f"{self.user1},@192.168.1.1,{self.user2}@127.0.0.1"
        result = self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", excluded_rules)

        # Clear log file
        self._clear_log_file()
        
        # Execute commands as both users
        self.redis_user1.set("multi_exclude_key1", "value1")
        self.redis_user2.set("multi_exclude_key2", "value2")
        
        # Admin user should still be logged
        self.redis_admin.set("admin_key", "admin_value")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check test users' commands should not be logged
        user1_logged = any(f"multi_exclude_key1" in line for line in log_lines)
        user2_logged = any(f"multi_exclude_key2" in line for line in log_lines)
        
        self.assertFalse(user1_logged, f"Excluded user {self.user1} was logged")
        self.assertFalse(user2_logged, f"Excluded user {self.user2} was logged when connecting from 127.0.0.1")
        
        # Admin should still be logged
        admin_logged = any(f"admin_key" in line for line in log_lines)
        self.assertTrue(admin_logged, "Admin user should be logged")

    def test_005_get_exclusion_rules(self):
        """Test retrieving the list of exclusion rules"""
        # Set a specific list of exclusion rules
        expected_rules = f"{self.user1},@127.0.0.1,{self.user2}@192.168.1.1"
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", expected_rules)
        
        # Get the current list
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.EXCLUDERULES")
        print(f"res:{result}")

        # The result is a list where the second element contains the comma-separated rules
        exclusion_rules_string = result[1]  # Get the actual value from the result list

        # Now normalize both strings for comparison
        result_normalized = re.sub(r',\s+', ',', exclusion_rules_string)
        expected_normalized = re.sub(r',\s+', ',', expected_rules)
                
        # Check if all expected rules are in the result
        for rule in expected_normalized.split(','):
            self.assertIn(rule, result_normalized, f"Rule {rule} not found in exclusion rules list")

    def test_006_clear_exclusion_rules(self):
        """Test clearing the exclusion rules list"""
        # First exclude some users and IPs
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", f"{self.user1},@127.0.0.1")
        
        # Clear the exclusion rules list
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES","")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute command as previously excluded user
        self.redis_user1.set("after_clear_key", "value")

        # Read log file
        log_lines = self._read_log_file()
        
        # Check that the previously excluded user is now logged
        user_logged = any(f"after_clear_key" in line for line in log_lines)
        self.assertTrue(user_logged, "Previously excluded user should now be logged")

    def test_007_invalid_ip_handling(self):
        """Test handling of invalid IP addresses in exclusion rules"""
        # Try to set rules with invalid IP addresses
        invalid_rules = f"{self.user1}@999.999.999.999,@not.an.ip.address"
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", invalid_rules)
        
        # Valid rule should still be added
        valid_rule = f"{self.user1}"
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", valid_rule)
        
        # Get the current rules
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.EXCLUDERULES")
        exclusion_rules_string = result[1]
        
        # Check that invalid IPs were not added
        self.assertNotIn("999.999.999.999", exclusion_rules_string, "Invalid IP should not be in rules")
        self.assertNotIn("not.an.ip.address", exclusion_rules_string, "Invalid IP should not be in rules")
        
        # Check that valid username was added
        self.assertIn(self.user1, exclusion_rules_string, "Valid username should be in rules")

    def test_008_ipv6_support(self):
        """Test IPv6 address support in exclusion rules"""
        # Set rules with IPv6 addresses (using standard localhost IPv6)
        ipv6_rules = f"@::1,{self.user1}@::1"
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", ipv6_rules)
        
        # Get the current rules
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.EXCLUDERULES")
        exclusion_rules_string = result[1]
        
        # Check that IPv6 addresses were added correctly
        self.assertIn("::1", exclusion_rules_string, "IPv6 address should be in rules")
        
        # If using IPv6 for testing, we could also test actual command exclusion here
        # But that would require connecting to Redis over IPv6, which may not be available in all test environments

    def test_009_excluded_user_specific_commands(self):
        """Test that excluded clients' specific commands aren't logged but others are"""
        # Set user1 as excluded by username only
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", self.user1)
        
        # Ensure all categories are enabled
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute different types of commands as the excluded user
        # Key operations
        self.redis_user1.set("user1_excluded_key", "value")
        # Config operations
        try:
            self.redis_user1.execute_command("CONFIG", "GET", "port")
        except:
            pass  # Might fail if user doesn't have CONFIG permission, but should still attempt
        
        # Execute same commands as non-excluded user
        self.redis_user2.set("non_excluded_key", "value")
        try:
            self.redis_user2.execute_command("CONFIG", "GET", "port")
        except:
            pass
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check excluded user's commands are not logged
        excluded_key_logged = any(f"user1_excluded_key" in line for line in log_lines)
        self.assertFalse(excluded_key_logged, "Excluded user's key operation was logged")
        
        # Check non-excluded user's commands are logged
        non_excluded_key_logged = any(f"non_excluded_key" in line for line in log_lines)
        self.assertTrue(non_excluded_key_logged, "Non-excluded user's key operation was not logged")

if __name__ == "__main__":
    unittest.main(verbosity=2)
