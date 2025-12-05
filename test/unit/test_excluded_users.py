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
        cls.redis_admin.execute_command("ACL","SAVE")
        cls.redis_admin.execute_command("CONFIG","REWRITE")
        if hasattr(cls, 'server_proc'):
            cls.server_proc.terminate()
            cls.server_proc.wait(timeout=5)
        
        # Remove the temporary ACL file
        #try:
        #    os.remove("/tmp/valkey-acl-test.acl")
        #except:
        #    pass
    
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

    def test_010_always_audit_config_commands(self):
        """Test that CONFIG commands are always audited when always_audit_config is enabled"""
        # Set format to text for easier parsing
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Enable all event types
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        # Exclude user1 from audit
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", self.user1)
        
        # Ensure always_audit_config is enabled (default)
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.ALWAYS_AUDIT_CONFIG", "yes")
        
        # Clear log file
        self._clear_log_file()
        self.redis_admin.execute_command("auditusers")

        # Execute normal and CONFIG commands as excluded user
        self.redis_user1.set("excluded_key", "value")  # This should NOT be logged
        
        # Execute a CONFIG command as excluded user (may require privileges)
        try:
            self.redis_user1.execute_command("CONFIG", "GET", "port")  # This should be logged despite exclusion
        except:
            pass  # Might fail if user doesn't have permission, but should still attempt
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check normal command is NOT logged (user is excluded)
        normal_cmd_logged = any(f"excluded_key" in line for line in log_lines)
        self.assertFalse(normal_cmd_logged, "Excluded user's normal command was logged")
        
        # Check CONFIG command IS logged despite user exclusion
        config_cmd_logged = any(f"CONFIG" in line and self.user1 in line for line in log_lines)
        self.assertTrue(config_cmd_logged, "Excluded user's CONFIG command was not logged despite always_audit_config=yes")
        
        # Now disable always_audit_config
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.ALWAYS_AUDIT_CONFIG", "no")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute CONFIG command again
        try:
            self.redis_user1.execute_command("CONFIG", "GET", "port")  # This should NOT be logged now
        except:
            pass
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check CONFIG command is NOT logged when always_audit_config is disabled
        config_cmd_logged = any(f"CONFIG" in line and self.user1 in line for line in log_lines)
        self.assertFalse(config_cmd_logged, "Excluded user's CONFIG command was logged despite always_audit_config=no")

    def test_011_always_audit_config_with_ip_exclusion(self):
        """Test always_audit_config with IP-based exclusion"""
        # Set format to text for easier parsing
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.FORMAT", "text")
        
        # Enable all event types
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EVENTS", "all")
        
        # Exclude localhost IP address
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.EXCLUDERULES", "@127.0.0.1")
        
        # Ensure always_audit_config is enabled
        self.redis_admin.execute_command("CONFIG","SET","AUDIT.ALWAYS_AUDIT_CONFIG", "yes")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute normal and CONFIG commands
        self.redis_user1.set("ip_excluded_key", "value")  # This should NOT be logged
        
        # Execute a CONFIG command (may require privileges)
        try:
            self.redis_user1.execute_command("CONFIG", "GET", "port")  # This should be logged despite IP exclusion
        except:
            pass
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check normal command is NOT logged (IP is excluded)
        normal_cmd_logged = any(f"ip_excluded_key" in line for line in log_lines)
        self.assertFalse(normal_cmd_logged, "Command from excluded IP was logged")
        
        # Check CONFIG command IS logged despite IP exclusion
        config_cmd_logged = any(f"CONFIG" in line for line in log_lines)
        self.assertTrue(config_cmd_logged, "CONFIG command from excluded IP was not logged despite always_audit_config=yes")
    
    def test_012_exclude_specific_commands(self):
        """Test excluding specific commands from audit"""
        # Set format to text for easier parsing
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Enable all event types
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        
        # Clear any user exclusions
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        
        # Exclude specific commands
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "PING,ECHO,INFO")

        # Clear log file
        self._clear_log_file()
        
        # Execute excluded commands
        self.redis_user1.ping()
        self.redis_user1.echo("test message")
        try:
            self.redis_user1.info()
        except:
            pass
        
        # Execute non-excluded commands
        self.redis_user1.set("excluded_cmd_test", "value")
        self.redis_user1.get("excluded_cmd_test")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check that excluded commands are NOT logged
        ping_logged = any("PING" in line for line in log_lines)
        echo_logged = any("ECHO" in line for line in log_lines)
        
        self.assertFalse(ping_logged, "Excluded PING command was logged")
        self.assertFalse(echo_logged, "Excluded ECHO command was logged")
        
        # Check that non-excluded commands ARE logged
        set_logged = any("SET" in line and "excluded_cmd_test" in line for line in log_lines)
        get_logged = any("GET" in line and "excluded_cmd_test" in line for line in log_lines)
        
        self.assertTrue(set_logged, "Non-excluded SET command was not logged")
        self.assertTrue(get_logged, "Non-excluded GET command was not logged")
        
        # Clear exclusions
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")

    def test_013_exclude_commands_case_insensitive(self):
        """Test that command exclusion is case-insensitive"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        
        # Exclude commands using mixed case
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "PiNg,eCHo")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands in various cases
        self.redis_user1.execute_command("PING")
        self.redis_user1.execute_command("ping")
        self.redis_user1.execute_command("echo", "test")
        self.redis_user1.execute_command("ECHO", "test")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # None should be logged
        ping_logged = any("PING" in line.upper() for line in log_lines)
        echo_logged = any("ECHO" in line.upper() for line in log_lines)
        
        self.assertFalse(ping_logged, "PING command was logged despite exclusion")
        self.assertFalse(echo_logged, "ECHO command was logged despite exclusion")
        
        # Clear exclusions
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")

    def test_014_prefix_filter_exclusion(self):
        """Test prefix-based command filtering with exclusion"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        
        # Exclude all DEBUG and CLIENT commands using prefix filter
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!DEBUG*,!CLIENT*")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands that should be excluded by prefix
        try:
            self.redis_user1.execute_command("CLIENT", "LIST")
        except:
            pass
        
        # Execute commands that should NOT be excluded
        self.redis_user1.set("prefix_test_key", "value")
        self.redis_user1.get("prefix_test_key")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check that prefix-matched commands are NOT logged
        client_logged = any("CLIENT" in line for line in log_lines)
        self.assertFalse(client_logged, "Command matching exclusion prefix was logged")
        
        # Check that non-matching commands ARE logged
        set_logged = any("SET" in line and "prefix_test_key" in line for line in log_lines)
        get_logged = any("GET" in line and "prefix_test_key" in line for line in log_lines)
        
        self.assertTrue(set_logged, "Non-excluded SET command was not logged")
        self.assertTrue(get_logged, "Non-excluded GET command was not logged")
        
        # Clear prefix filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_015_prefix_filter_multiple_patterns(self):
        """Test multiple prefix patterns"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        
        # Exclude multiple command prefixes
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", 
                                        "!CLIENT*,!DEBUG*,!CLUSTER*")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands matching different prefixes
        try:
            self.redis_user1.execute_command("CLIENT", "LIST")
            self.redis_user1.execute_command("CLUSTER", "INFO")
        except:
            pass
        
        # Execute non-matching command
        self.redis_user1.set("multi_prefix_key", "value")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Check that all prefix-matched commands are NOT logged
        client_logged = any("CLIENT" in line for line in log_lines)
        cluster_logged = any("CLUSTER" in line for line in log_lines)
        
        self.assertFalse(client_logged, "CLIENT command was logged despite prefix exclusion")
        self.assertFalse(cluster_logged, "CLUSTER command was logged despite prefix exclusion")
        
        # Check that non-matching command IS logged
        set_logged = any("SET" in line and "multi_prefix_key" in line for line in log_lines)
        self.assertTrue(set_logged, "Non-excluded command was not logged")
        
        # Clear prefix filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_016_custom_category_definition(self):
        """Test defining and using custom categories"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Define a custom category for dangerous commands
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY",
                                        "dangerous:FLUSHDB,FLUSHALL,SHUTDOWN")
        
        # Enable only the dangerous category (disable others)
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "dangerous")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute normal commands (should NOT be logged)
        self.redis_user1.set("custom_cat_key", "value")
        self.redis_user1.get("custom_cat_key")
        
        # We can't actually execute FLUSHDB in tests without clearing data,
        # but we can verify the configuration worked
        
        # Re-enable all events
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        
        # Execute normal command again (should be logged now)
        self.redis_user1.set("custom_cat_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # First key should NOT be logged (events was set to dangerous only)
        first_key_logged = any("custom_cat_key" in line and "custom_cat_key2" not in line 
                               for line in log_lines)
        self.assertFalse(first_key_logged, 
                        "Command was logged when only dangerous category was enabled")
        
        # Second key should be logged (events set to all)
        second_key_logged = any("custom_cat_key2" in line for line in log_lines)
        self.assertTrue(second_key_logged, 
                       "Command was not logged when all events enabled")
        
        # Clear custom categories
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", "")

    def test_017_custom_category_with_existing_events(self):
        """Test that custom categories work alongside built-in event types"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Define custom category
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY",
                                        "admin:CONFIG,ACL")
        
        # Enable both built-in and custom categories
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "keys,admin")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands from different categories
        self.redis_user1.set("mixed_cat_key", "value")  # keys category
        try:
            self.redis_user1.execute_command("CONFIG", "GET", "port")  # admin category
        except:
            pass
        
        # Read log file
        log_lines = self._read_log_file()
        
        # Both should be logged
        key_logged = any("SET" in line and "mixed_cat_key" in line for line in log_lines)
        config_logged = any("CONFIG" in line for line in log_lines)
        
        self.assertTrue(key_logged, "Key command not logged with keys,admin events")
        self.assertTrue(config_logged, "CONFIG command not logged with keys,admin events")
        
        # Clear custom categories
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
    
    def test_018_combined_user_and_command_exclusion(self):
        """Test combining user exclusion with command exclusion"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        
        # Exclude user1
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", self.user1)
        
        # Also exclude PING command
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "PING")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands as excluded user
        self.redis_user1.ping()
        self.redis_user1.set("combined_exclude_key1", "value1")
        
        # Execute commands as non-excluded user
        self.redis_user2.ping()
        self.redis_user2.set("combined_exclude_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # User1's commands should NOT be logged (user excluded)
        user1_set_logged = any("combined_exclude_key1" in line for line in log_lines)
        self.assertFalse(user1_set_logged, "Excluded user's SET was logged")
        
        # User2's PING should NOT be logged (command excluded)
        user2_ping_logged = any("PING" in line and self.user2 in line for line in log_lines)
        self.assertFalse(user2_ping_logged, "Excluded command PING was logged")
        
        # User2's SET should be logged
        user2_set_logged = any("SET" in line and "combined_exclude_key2" in line 
                               for line in log_lines)
        self.assertTrue(user2_set_logged, "Non-excluded user's SET was not logged")
        
        # Clear exclusions
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")
    
    def test_019_prefix_filter_with_user_exclusion(self):
        """Test prefix filter combined with user exclusion"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        
        # Exclude user1
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", self.user1)
        
        # Exclude CLIENT commands via prefix filter
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!CLIENT*")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute commands as excluded user
        try:
            self.redis_user1.execute_command("CLIENT", "LIST")
        except:
            pass
        self.redis_user1.set("prefix_user_exclude_key1", "value1")
        
        # Execute commands as non-excluded user
        try:
            self.redis_user2.execute_command("CLIENT", "LIST")
        except:
            pass
        self.redis_user2.set("prefix_user_exclude_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        for line in log_lines:
            print(f"log_line:{line}")

        # User1's commands should NOT be logged (user excluded)
        user1_logged = any("prefix_user_exclude_key1" in line for line in log_lines)
        self.assertFalse(user1_logged, "Excluded user's command was logged")
        
        # User2's CLIENT command should NOT be logged (prefix excluded)
        user2_client_logged = any("CLIENT" in line and self.user2 in line for line in log_lines)
        self.assertFalse(user2_client_logged, "Prefix-excluded command was logged")
        
        # User2's SET should be logged
        user2_set_logged = any("SET" in line and "prefix_user_exclude_key2" in line 
                               for line in log_lines)
        self.assertTrue(user2_set_logged, "Non-excluded command was not logged")
        
        # Clear filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_020_get_exclude_commands_config(self):
        """Test retrieving excluded commands configuration"""
        # Set excluded commands
        excluded_cmds = "PING,ECHO,INFO,TIME"
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", excluded_cmds)
        
        # Retrieve the configuration
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.EXCLUDE_COMMANDS")
        
        # Result is a list [key, value]
        actual_value = result[1]
        
        # Normalize both for comparison
        expected_cmds = set(excluded_cmds.lower().split(','))
        actual_cmds = set(actual_value.lower().split(','))
        
        print(f"expected:{expected_cmds}, actual:{actual_cmds}")
        self.assertEqual(expected_cmds, actual_cmds, 
                        "Retrieved excluded commands don't match what was set")
        
        # Clear exclusions
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")

    def test_021_get_prefix_filter_config(self):
        """Test retrieving prefix filter configuration"""
        # Set prefix filters
        prefix_filters = "!DEBUG*,!CLIENT*,!CLUSTER*"
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", prefix_filters)
        
        # Retrieve the configuration
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.PREFIX_FILTER")
        
        # Result is a list [key, value]
        actual_value = result[1]
        
        # Normalize both for comparison
        expected_filters = set(prefix_filters.split(','))
        actual_filters = set(actual_value.split(','))
        
        self.assertEqual(expected_filters, actual_filters,
                        "Retrieved prefix filters don't match what was set")
        
        # Clear filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_022_get_custom_category_config(self):
        """Test retrieving custom category configuration"""
        # Set custom category
        custom_cat = "dangerous:FLUSHDB,FLUSHALL,SHUTDOWN"
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", custom_cat)
        
        # Retrieve the configuration
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.CUSTOM_CATEGORY")
        
        # Result is a list [key, value]
        actual_value = result[1]
        
        # Should contain the category definition
        self.assertIn("dangerous", actual_value.lower(), "Custom category name not found")
        self.assertIn("flushdb", actual_value.lower(), "FLUSHDB not found in category")
        self.assertIn("flushall", actual_value.lower(), "FLUSHALL not found in category")
        
        # Clear custom categories
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", "")

    def test_023_clear_all_filters(self):
        """Test clearing all filter configurations"""
        # Set all types of filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", self.user1)
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "PING,ECHO")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!DEBUG*")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", 
                                        "test:FLUSHDB")
        
        # Clear all filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", "")
        
        # Verify all are cleared
        rules = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.EXCLUDERULES")[1]
        commands = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.EXCLUDE_COMMANDS")[1]
        prefixes = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.PREFIX_FILTER")[1]
        categories = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.CUSTOM_CATEGORY")[1]
        
        self.assertEqual(rules, "", "Exclusion rules not cleared")
        self.assertEqual(commands, "", "Excluded commands not cleared")
        self.assertEqual(prefixes, "", "Prefix filters not cleared")
        self.assertEqual(categories, "", "Custom categories not cleared")

    def test_024_always_audit_config_overrides_command_exclusion(self):
        """Test that always_audit_config overrides command exclusion for CONFIG commands"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "keys")
        
        # Enable always_audit_config
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.ALWAYS_AUDIT_CONFIG", "yes")
        
        result = self.redis_admin.execute_command("CONFIG", "GET", "AUDIT.*")
        print(f"res:{result}")

        # Clear log file
        log_lines = self._read_log_file()
        for line in log_lines:
            print(f"LOG LINE: {line}")
        #self._clear_log_file()
        
        # Execute CONFIG command
        result = self.redis_user1.execute_command("CONFIG", "GET", "port")
        print(f"CONFIG RESULT: {result}")
        
        # Read log file
        log_lines = self._read_log_file()
        for line in log_lines:
            print(f"LOG LINE: {line}")

        # CONFIG should be logged 
        config_logged = any("CONFIG" in line for line in log_lines)
        self.assertTrue(config_logged, 
                       "CONFIG command not logged despite always_audit_config=yes")
        
        # Now disable always_audit_config
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.ALWAYS_AUDIT_CONFIG", "no")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute CONFIG command again
        self.redis_user1.execute_command("CONFIG", "GET", "port")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # CONFIG should NOT be logged now
        config_logged = any("CONFIG" in line for line in log_lines)
        self.assertFalse(config_logged,
                        "CONFIG command logged when excluded and always_audit_config=no")
        
        # Clear exclusions
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")

    def test_025_always_audit_config_overrides_prefix_filter(self):
        """Test that always_audit_config overrides prefix filter for CONFIG commands"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        
        # Exclude CONFIG via prefix filter
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!CONFIG*")
        
        # Enable always_audit_config
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.ALWAYS_AUDIT_CONFIG", "yes")
        
        # Clear log file
        self._clear_log_file()
        
        # Execute CONFIG command
        self.redis_user1.execute_command("CONFIG", "GET", "port")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # CONFIG should be logged despite prefix filter
        config_logged = any("CONFIG" in line for line in log_lines)
        self.assertTrue(config_logged,
                       "CONFIG command not logged despite always_audit_config=yes with prefix filter")
        
        # Clear filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_026_filter_priority_order(self):
        """Test the priority order of different filter types"""
        # Set format to text
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        
        # Set up multiple overlapping filters:
        # 1. Exclude user1
        # 2. Exclude PING command
        # 3. Exclude DEBUG* prefix
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", self.user1)
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "PING")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "!DEBUG*")
        
        # Clear log file
        self._clear_log_file()
        
        # Test 1: User exclusion should take precedence (user1 doing anything)
        self.redis_user1.set("priority_test_key1", "value1")
        self.redis_user1.ping()
        
        # Test 2: Non-excluded user with excluded command
        self.redis_user2.ping()
        
        # Test 3: Non-excluded user with non-excluded command
        self.redis_user2.set("priority_test_key2", "value2")
        
        # Read log file
        log_lines = self._read_log_file()
        
        # User1's commands should NOT be logged (highest priority: user exclusion)
        user1_logged = any(self.user1 in line for line in log_lines)
        self.assertFalse(user1_logged, "Excluded user's commands were logged")
        
        # User2's PING should NOT be logged (command exclusion)
        user2_ping_logged = any("PING" in line and self.user2 in line for line in log_lines)
        self.assertFalse(user2_ping_logged, "Excluded command was logged")
        
        # User2's SET should be logged
        user2_set_logged = any("SET" in line and "priority_test_key2" in line 
                               for line in log_lines)
        self.assertTrue(user2_set_logged, "Non-excluded command was not logged")
        
        # Clear all filters
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")

    def test_027_empty_filter_configurations(self):
        """Test behavior with empty filter configurations"""
        # Set all filters to empty
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDERULES", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EXCLUDE_COMMANDS", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.PREFIX_FILTER", "")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.CUSTOM_CATEGORY", "")
        
        # Enable all events
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.EVENTS", "all")
        self.redis_admin.execute_command("CONFIG", "SET", "AUDIT.FORMAT", "text")
        
        # Clear log file
        self._clear_log_file()
        
        config = self.redis_admin.execute_command("CONFIG GET AUDIT.*")
        
        # Check structure - Redis returns flat key-value pairs
        self.assertEqual(len(config), 40, "Config should have 40 items")
        
        # Convert flat array to dictionary (every two elements form a key-value pair)
        config_dict = {}
        for i in range(0, len(config), 2):
            key = config[i]
            value = config[i + 1]
            config_dict[key] = value
        
        # Debug output
        for key, value in config_dict.items():
            print(f"{key}: {value}")

        # Execute commands
        self.redis_user1.set("empty_filter_key", "value")
        self.redis_user1.ping()
        
        # Read log file
        log_lines = self._read_log_file()

        for line in log_lines:
            print(line)
        
        # All commands should be logged when no filters are active
        set_logged = any("set" in line.lower() and "empty_filter_key" in line for line in log_lines)
        ping_logged = any("ping" in line.lower() for line in log_lines)
        
        self.assertTrue(set_logged, "SET command not logged with empty filters")
        self.assertTrue(ping_logged, "PING command not logged with empty filters")

if __name__ == "__main__":
    unittest.main(verbosity=2)
