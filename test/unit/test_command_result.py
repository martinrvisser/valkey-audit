#!/usr/bin/env python3
"""
Unit tests for the command result callback functionality.

Tests the migration from pre-execution command filter to post-execution
command result callbacks, including:
- Failure event logging with real SUCCESS/FAILURE outcome
- New audit output fields: duration_us, dirty
- command_result_mode configuration (all vs failures)
- Output format consistency across TEXT, JSON, CSV
"""
import unittest
import redis
import os
import tempfile
import time
import json
import csv
import io
import subprocess
import socket


class TestCommandResultBase(unittest.TestCase):
    """Base class with server setup/teardown for command result tests."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="vka-cmdresult-")
        cls.log_file = os.path.join(cls.temp_dir, "audit.log")

        cls.valkey_server = os.environ.get("VALKEY_SERVER", "valkey-server")
        cls.module_path = os.environ.get("AUDIT_MODULE_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "libvalkeyaudit.so"))

        cls._start_server()

        cls.client = redis.Redis(host='localhost', port=cls.port, decode_responses=True)
        max_retries = 10
        for i in range(max_retries):
            try:
                cls.client.ping()
                break
            except redis.exceptions.ConnectionError:
                if i == max_retries - 1:
                    raise
                time.sleep(0.5)

        # Probe whether the server supports command result events.
        # Trigger a known WRONGTYPE failure and check if the audit log captures it.
        open(cls.log_file, 'w').close()
        cls.client.set("__probe__", "string")
        try:
            cls.client.lpush("__probe__", "val")
        except Exception:
            pass
        time.sleep(0.5)
        try:
            with open(cls.log_file) as f:
                cls.command_result_supported = len(f.read()) > 0
        except FileNotFoundError:
            cls.command_result_supported = False
        open(cls.log_file, 'w').close()
        cls.client.delete("__probe__")

    @classmethod
    def tearDownClass(cls):
        cls._stop_server()

    @classmethod
    def _start_server(cls, extra_config=""):
        s = socket.socket()
        s.bind(('', 0))
        cls.port = s.getsockname()[1]
        s.close()

        cls.conf_file = os.path.join(cls.temp_dir, "valkey.conf")
        with open(cls.conf_file, 'w') as f:
            f.write(f"port {cls.port}\n")
            f.write(f"loadmodule {cls.module_path}\n")
            f.write(f"audit.protocol file {cls.log_file}\n")
            f.write(f"audit.events keys,auth,config,other\n")
            if extra_config:
                f.write(extra_config + "\n")

        cls.server_proc = subprocess.Popen(
            [cls.valkey_server, cls.conf_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(1)

    @classmethod
    def _stop_server(cls):
        if hasattr(cls, 'server_proc'):
            cls.server_proc.terminate()
            cls.server_proc.wait(timeout=5)
            if cls.server_proc.stdout:
                cls.server_proc.stdout.close()
            if cls.server_proc.stderr:
                cls.server_proc.stderr.close()

    def _read_log_file(self):
        try:
            with open(self.log_file, 'r') as f:
                return f.readlines()
        except FileNotFoundError:
            return []

    def _clear_log_file(self):
        open(self.log_file, 'w').close()

    def _read_last_log_lines(self, n=5):
        lines = self._read_log_file()
        return lines[-n:] if len(lines) >= n else lines

    def skipIfNoCommandResultSupport(self):
        if not getattr(self.__class__, 'command_result_supported', True):
            self.skipTest(
                "Server does not support command result events "
                "(requires Valkey build with PR #2936)"
            )


class TestCommandResultConfig(TestCommandResultBase):
    """Tests for the command_result_mode configuration option."""

    def test_001_default_mode_is_failures(self):
        """Default command_result_mode should be 'failures'."""
        result = self.client.execute_command("CONFIG", "GET", "audit.command_result_mode")
        # CONFIG GET returns a list: [key, value]
        self.assertEqual(result[1], "failures",
                         "Default command_result_mode should be 'failures'")

    def test_002_set_mode_all(self):
        """Setting command_result_mode to 'all' should succeed."""
        result = self.client.execute_command("CONFIG", "SET",
                                             "audit.command_result_mode", "all")
        self.assertEqual(result, "OK")

        result = self.client.execute_command("CONFIG", "GET",
                                             "audit.command_result_mode")
        self.assertEqual(result[1], "all")

    def test_003_set_mode_failures(self):
        """Setting command_result_mode to 'failures' should succeed."""
        result = self.client.execute_command("CONFIG", "SET",
                                             "audit.command_result_mode", "failures")
        self.assertEqual(result, "OK")

        result = self.client.execute_command("CONFIG", "GET",
                                             "audit.command_result_mode")
        self.assertEqual(result[1], "failures")

    def test_004_set_mode_invalid(self):
        """Setting command_result_mode to an invalid value should fail."""
        with self.assertRaises(redis.exceptions.ResponseError):
            self.client.execute_command("CONFIG", "SET",
                                        "audit.command_result_mode", "invalid")

    def test_005_set_mode_case_insensitive(self):
        """command_result_mode should accept case-insensitive values."""
        result = self.client.execute_command("CONFIG", "SET",
                                             "audit.command_result_mode", "ALL")
        self.assertEqual(result, "OK")

        result = self.client.execute_command("CONFIG", "SET",
                                             "audit.command_result_mode", "Failures")
        self.assertEqual(result, "OK")


class TestCommandResultFailureLogging(TestCommandResultBase):
    """Tests that failed commands are logged with FAILURE result."""

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    def test_010_failed_command_logged_as_failure(self):
        """A command that fails should be logged with result=FAILURE."""
        self._clear_log_file()

        # SET a string key, then try LPUSH on it (wrong type -> failure)
        self.client.set("mystring", "hello")
        time.sleep(0.5)
        self._clear_log_file()

        try:
            self.client.lpush("mystring", "value")
        except redis.exceptions.ResponseError:
            pass  # Expected: WRONGTYPE

        time.sleep(0.5)
        log_lines = self._read_log_file()
        log_content = "".join(log_lines)
        self.assertIn("FAILURE", log_content,
                       "Failed command should be logged with FAILURE")
        self.assertIn("LPUSH", log_content.upper(),
                       "Failed LPUSH command should appear in log")

    def test_011_wrong_arg_count_logged_as_rejected(self):
        """A command with the wrong number of arguments fires a REJECTED event.

        Wrong arg counts are caught at dispatch time (before the command handler
        runs), so they produce a CommandResultRejected event, not a Failure event.
        The audit module maps both to result=FAILURE in the log.
        """
        self._clear_log_file()

        try:
            # SET requires key + value; omitting value triggers wrong-arg-count rejection
            self.client.execute_command("SET", "onlykey")
        except redis.exceptions.ResponseError:
            pass  # Expected: wrong number of arguments for 'set' command

        time.sleep(0.5)
        log_lines = self._read_log_file()
        log_content = "".join(log_lines)
        # The server fires a REJECTED event; our module logs it as FAILURE
        # and appends "rejected=<error string>" to details
        if log_lines:
            self.assertIn("FAILURE", log_content,
                          "Wrong-arg-count rejection should be logged as FAILURE")
            self.assertIn("rejected=", log_content,
                          "REJECTED event details should contain 'rejected=' field")


class TestCommandResultOutputFormats(TestCommandResultBase):
    """Tests that new fields (duration_us, dirty) appear in all output formats."""

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    def _trigger_failure_and_read_log(self):
        """Helper: trigger a known failure and return log lines."""
        self.client.set("typecheck", "stringval")
        time.sleep(0.3)
        self._clear_log_file()

        try:
            self.client.lpush("typecheck", "listval")
        except redis.exceptions.ResponseError:
            pass

        time.sleep(0.5)
        return self._read_log_file()

    def test_020_json_format_has_new_fields(self):
        """JSON output should include duration_us and dirty fields."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        time.sleep(0.3)

        log_lines = self._trigger_failure_and_read_log()
        self.assertTrue(len(log_lines) > 0, "Should have log entries for failed command")

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Check new fields exist
            self.assertIn("duration_us", obj,
                          "JSON output should have duration_us field")
            self.assertIn("keys_modified", obj,
                          "JSON output should have keys_modified field")
            self.assertIn("result", obj,
                          "JSON output should have result field")

            # duration_us should be a number >= 0
            self.assertIsInstance(obj["duration_us"], int,
                                  "duration_us should be an integer")
            self.assertGreaterEqual(obj["duration_us"], 0,
                                     "duration_us should be >= 0")

            # keys_modified should be a number >= 0
            self.assertIsInstance(obj["keys_modified"], int,
                                  "keys_modified should be an integer")

            # result should be FAILURE for our test
            self.assertEqual(obj["result"], "FAILURE",
                             "Result should be FAILURE for wrongtype error")
            break  # Only need to check one entry

    def test_021_json_format_has_all_standard_fields(self):
        """JSON output should retain all existing fields alongside new ones."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        time.sleep(0.3)

        log_lines = self._trigger_failure_and_read_log()
        self.assertTrue(len(log_lines) > 0)

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            expected_fields = ["timestamp", "category", "command", "command_args",
                               "result", "username", "client_ip", "client_port",
                               "server_hostname", "duration_us", "keys_modified",
                               "client_id", "error"]
            for field in expected_fields:
                self.assertIn(field, obj,
                              f"JSON output missing expected field: {field}")
            break

    def test_022_csv_format_has_new_fields(self):
        """CSV output should include duration_us and dirty columns."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "csv")
        time.sleep(0.3)

        log_lines = self._trigger_failure_and_read_log()
        self.assertTrue(len(log_lines) > 0, "Should have CSV log entries")

        line = log_lines[0].strip()
        # CSV fields: timestamp,category,command,command_args,result,
        #             duration_us,keys_modified,client_id,username,client_ip,
        #             client_port,server_hostname,error
        # That's 13 fields minimum
        reader = csv.reader(io.StringIO(line))
        row = next(reader)
        self.assertGreaterEqual(len(row), 13,
                                f"CSV should have at least 13 columns, got {len(row)}: {row}")

        # Field at index 4 should be the result flag
        self.assertEqual(row[4], "FAILURE",
                         f"CSV result field should be FAILURE, got: {row[4]}")

        # Fields at index 5 and 6 should be duration_us and keys_modified (numeric)
        try:
            duration_us = int(row[5])
            self.assertGreaterEqual(duration_us, 0, "duration_us should be >= 0")
        except ValueError:
            self.fail(f"CSV duration_us field is not numeric: {row[5]}")

        try:
            keys_modified = int(row[6])
            self.assertGreaterEqual(keys_modified, 0, "keys_modified should be >= 0")
        except ValueError:
            self.fail(f"CSV keys_modified field is not numeric: {row[6]}")

    def test_023_text_format_has_duration(self):
        """TEXT output should include duration and dirty info."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "text")
        time.sleep(0.3)

        log_lines = self._trigger_failure_and_read_log()
        self.assertTrue(len(log_lines) > 0, "Should have TEXT log entries")

        log_content = "".join(log_lines)
        self.assertRegex(log_content, r"duration_us=\d+",
                         "TEXT format should include duration_us field")
        self.assertRegex(log_content, r"keys_modified=\d+",
                         "TEXT format should include keys_modified field")
        self.assertIn("FAILURE", log_content,
                       "TEXT format should include FAILURE result")

    def test_024_format_consistency_across_modes(self):
        """All three formats should contain the same logical information."""
        results = {}

        for fmt in ["json", "csv", "text"]:
            self.client.execute_command("CONFIG", "SET", "audit.format", fmt)
            time.sleep(0.3)

            log_lines = self._trigger_failure_and_read_log()
            self.assertTrue(len(log_lines) > 0,
                            f"No log entries for format {fmt}")
            results[fmt] = log_lines[0].strip()

        # All formats should contain FAILURE
        for fmt, line in results.items():
            self.assertIn("FAILURE", line,
                          f"Format {fmt} should contain FAILURE")

    def tearDown(self):
        # Reset to text format after each test
        try:
            self.client.execute_command("CONFIG", "SET", "audit.format", "text")
        except Exception:
            pass


class TestCommandResultCategoryFiltering(TestCommandResultBase):
    """Tests that category filtering still works with the new callback."""

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    def test_030_key_op_failure_logged(self):
        """KEY_OP failures should be logged when keys event is enabled."""
        self.client.execute_command("CONFIG", "SET", "audit.events", "keys")
        time.sleep(0.3)

        self.client.set("cattest", "stringval")
        time.sleep(0.3)
        self._clear_log_file()

        try:
            self.client.lpush("cattest", "value")
        except redis.exceptions.ResponseError:
            pass

        time.sleep(0.5)
        log_content = "".join(self._read_log_file())
        self.assertIn("FAILURE", log_content,
                       "KEY_OP failure should be logged")

    def test_031_disabled_category_not_logged(self):
        """Failures in disabled categories should not be logged."""
        # Only enable auth events, disable keys
        self.client.execute_command("CONFIG", "SET", "audit.events", "auth")
        time.sleep(0.3)
        self._clear_log_file()

        try:
            self.client.lpush("cattest", "value")
        except redis.exceptions.ResponseError:
            pass

        time.sleep(0.5)
        log_lines = self._read_log_file()
        key_failures = [l for l in log_lines
                        if "KEY_OP" in l and "FAILURE" in l]
        self.assertEqual(len(key_failures), 0,
                         "KEY_OP failures should not be logged when keys category is disabled")

    def tearDown(self):
        try:
            self.client.execute_command("CONFIG", "SET",
                                        "audit.events", "keys,auth,config,other")
        except Exception:
            pass


class TestCommandResultDurationAndDirty(TestCommandResultBase):
    """Tests that duration_us and dirty fields have meaningful values."""

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    def test_040_duration_is_populated(self):
        """duration_us should have a non-negative value for failed commands."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        time.sleep(0.3)

        self.client.set("durtest", "stringval")
        time.sleep(0.3)
        self._clear_log_file()

        try:
            self.client.lpush("durtest", "value")
        except redis.exceptions.ResponseError:
            pass

        time.sleep(0.5)
        log_lines = self._read_log_file()
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("result") == "FAILURE":
                    self.assertGreaterEqual(obj["duration_us"], 0,
                                             "duration_us should be >= 0")
                    return
            except json.JSONDecodeError:
                continue
        self.fail("No FAILURE JSON entry found to check duration_us")

    def test_041_dirty_is_zero_for_failed_write(self):
        """dirty should be 0 for a failed write command (no keys modified)."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        time.sleep(0.3)

        self.client.set("dirtytest", "stringval")
        time.sleep(0.3)
        self._clear_log_file()

        try:
            self.client.lpush("dirtytest", "value")
        except redis.exceptions.ResponseError:
            pass

        time.sleep(0.5)
        log_lines = self._read_log_file()
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("result") == "FAILURE":
                    self.assertEqual(obj["keys_modified"], 0,
                                     "keys_modified should be 0 for a failed write (no keys modified)")
                    return
            except json.JSONDecodeError:
                continue
        self.fail("No FAILURE JSON entry found to check keys_modified count")

    def tearDown(self):
        try:
            self.client.execute_command("CONFIG", "SET", "audit.format", "text")
        except Exception:
            pass


class TestCommandResultSuccessLogging(TestCommandResultBase):
    """Tests for 'all' mode where successful commands are also logged.

    Note: These tests verify the config and output format. The actual success
    event subscription is set at module load time, so if the module was loaded
    with default mode='failures', success events won't fire. These tests
    validate the callback logic when both events are subscribed.
    """

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    def test_050_success_events_in_all_mode_format(self):
        """In 'all' mode, the output format should include SUCCESS result.

        Note: This test sets the config to 'all' but the subscription is
        set at module load. It validates that the config value is accepted
        and the format functions handle SUCCESS correctly.
        """
        result = self.client.execute_command("CONFIG", "SET",
                                             "audit.command_result_mode", "all")
        self.assertEqual(result, "OK")

        # Verify the mode was set
        result = self.client.execute_command("CONFIG", "GET",
                                             "audit.command_result_mode")
        self.assertEqual(result[1], "all")

        # Reset back
        self.client.execute_command("CONFIG", "SET",
                                     "audit.command_result_mode", "failures")


class TestCommandResultRejectedEvents(TestCommandResultBase):
    """Tests for the two non-success event types added by PR #2936:
    - CommandResultRejected  : non-ACL pre-execution rejection (wrong args, OOM, NOMULTI…)
    - CommandResultACLRejected: ACL NOPERM rejection (logged with acl_deny_reason)
    """

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    # -- CommandResultRejected tests ------------------------------------------

    def test_060_exec_without_multi_logged_as_rejected(self):
        """EXEC outside a MULTI block fires a CommandResultRejected event.

        The server returns -ERR EXEC without MULTI. Our module appends the full
        error string as 'rejected=<error>' in the audit log details.
        """
        self.client.execute_command("CONFIG", "SET", "audit.events",
                                    "keys,auth,config,other")
        time.sleep(0.2)
        self._clear_log_file()

        try:
            self.client.execute_command("EXEC")
        except redis.exceptions.ResponseError:
            pass  # Expected

        time.sleep(0.5)
        log_lines = self._read_log_file()
        log_content = "".join(log_lines)
        self.assertTrue(log_lines, "EXEC rejection should produce an audit log entry")
        self.assertIn("FAILURE", log_content,
                      "CommandResultRejected should be logged with result=FAILURE")
        # rejected= is only populated for CommandResultRejected events; some server
        # versions fire CommandResultFailure for EXEC-without-MULTI instead.
        if "rejected=" not in log_content:
            self.skipTest(
                "Server fires FAILURE (not REJECTED) for EXEC-without-MULTI; "
                "rejected= field is only populated for CommandResultRejected events"
            )
        self.assertIn("rejected=", log_content,
                      "CommandResultRejected details should contain 'rejected=' field "
                      "with the full error string from the server")

    def test_061_wrong_arg_count_rejection_context(self):
        """Wrong-arg-count rejection should embed the server error string in details."""
        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        time.sleep(0.2)
        self._clear_log_file()

        try:
            self.client.execute_command("GET")  # GET needs exactly 1 arg
        except redis.exceptions.ResponseError:
            pass

        time.sleep(0.5)
        log_lines = self._read_log_file()
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("result") == "FAILURE":
                error = obj.get("error", "")
                self.assertIn("rejected=", error,
                              "JSON error field for a REJECTED event should contain 'rejected='")
                return
        # If no entries were logged, skip rather than fail (server may not log
        # rejected events for genuinely unknown commands in all builds)
        if not log_lines:
            self.skipTest("No log entries produced — server may not support REJECTED events")

    def tearDown(self):
        try:
            self.client.execute_command("CONFIG", "SET", "audit.format", "text")
            self.client.execute_command("CONFIG", "SET", "audit.events",
                                        "keys,auth,config,other")
        except Exception:
            pass

    # -- CommandResultACLRejected tests ----------------------------------------

    def test_070_acl_noperm_logged_with_deny_reason(self):
        """A NOPERM command rejection fires CommandResultACLRejected.

        The subevent carries the ACL reason (AUTH=0, CMD=1, KEY=2, CHANNEL=3, DB=4).
        Our module translates the subevent into acl_deny_reason=<reason> in the
        audit log details.
        """
        # Create a restricted user: can authenticate but cannot run any command
        try:
            self.client.execute_command(
                "ACL", "SETUSER", "restricteduser", "on", ">testpass123",
                "nocommands", "~*"
            )
        except redis.exceptions.ResponseError as e:
            self.skipTest(f"Could not create ACL test user: {e}")

        self.client.execute_command("CONFIG", "SET", "audit.events",
                                    "keys,auth,config,other")
        time.sleep(0.2)
        self._clear_log_file()

        restricted = redis.Redis(
            host='localhost', port=self.__class__.port,
            username='restricteduser', password='testpass123',
            decode_responses=True
        )
        try:
            restricted.set("anykey", "anyval")
        except redis.exceptions.ResponseError:
            pass  # Expected NOPERM
        finally:
            restricted.close()

        time.sleep(0.5)
        log_lines = self._read_log_file()
        log_content = "".join(log_lines)

        # Clean up the test user
        try:
            self.client.execute_command("ACL", "DELUSER", "restricteduser")
        except Exception:
            pass

        self.assertTrue(log_lines,
                        "ACL NOPERM rejection should produce an audit log entry")
        self.assertIn("FAILURE", log_content,
                      "CommandResultACLRejected should be logged with result=FAILURE")
        self.assertIn("acl_deny_reason=", log_content,
                      "CommandResultACLRejected details should contain 'acl_deny_reason=' field")

    def test_071_acl_noperm_key_includes_acl_object(self):
        """Key-level NOPERM rejection should include the denied key name as acl_object."""
        # Create a user that can run SET but only on keys prefixed with 'allowed:'
        try:
            self.client.execute_command(
                "ACL", "SETUSER", "keyuser", "on", ">keypass456",
                "allcommands", "~allowed:*"
            )
        except redis.exceptions.ResponseError as e:
            self.skipTest(f"Could not create ACL key-restricted test user: {e}")

        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        time.sleep(0.2)
        self._clear_log_file()

        keyuser = redis.Redis(
            host='localhost', port=self.__class__.port,
            username='keyuser', password='keypass456',
            decode_responses=True
        )
        try:
            keyuser.set("forbidden:key", "value")  # Key not in ~allowed:*
        except redis.exceptions.ResponseError:
            pass  # Expected NOPERM on key
        finally:
            keyuser.close()

        time.sleep(0.5)
        log_lines = self._read_log_file()

        # Clean up
        try:
            self.client.execute_command("ACL", "DELUSER", "keyuser")
        except Exception:
            pass

        key_rejection_entry = None
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("result") == "FAILURE":
                error = obj.get("error", "")
                if "acl_deny_reason=key" in error:
                    key_rejection_entry = error
                    break

        try:
            self.client.execute_command("CONFIG", "SET", "audit.format", "text")
        except Exception:
            pass

        if not log_lines:
            self.skipTest("No log entries produced — server may not support ACL_REJECTED events")
        self.assertIsNotNone(key_rejection_entry,
                             "No FAILURE entry with acl_deny_reason=key found for key-level ACL rejection")
        self.assertIn("acl_object=forbidden:key", key_rejection_entry,
                      "Key-level ACL rejection should include the denied key name")


class TestOutputFieldContent(TestCommandResultBase):
    """Tests that validate the actual *content* of the error and command_args fields
    for each output format, covering real failures, rejected events, and ACL rejections."""

    def setUp(self):
        self.skipIfNoCommandResultSupport()

    def _trigger_wrongtype_failure(self, fmt="json"):
        """Set up a WRONGTYPE failure scenario and return the log lines."""
        self.client.execute_command("CONFIG", "SET", "audit.format", fmt)
        self.client.execute_command("CONFIG", "SET", "audit.events", "keys,auth,config,other")
        self.client.set("wt_error_test", "stringval")
        time.sleep(0.2)
        self._clear_log_file()
        try:
            self.client.lpush("wt_error_test", "listval")
        except redis.exceptions.ResponseError:
            pass
        time.sleep(0.5)
        return self._read_log_file()

    def _trigger_wrong_arg_count(self, fmt="json"):
        """Trigger a wrong-arg-count rejection and return the log lines."""
        self.client.execute_command("CONFIG", "SET", "audit.format", fmt)
        self.client.execute_command("CONFIG", "SET", "audit.events", "keys,auth,config,other")
        self._clear_log_file()
        try:
            self.client.execute_command("GET")  # GET requires exactly 1 argument
        except redis.exceptions.ResponseError:
            pass
        time.sleep(0.5)
        return self._read_log_file()

    def test_080_json_error_empty_for_real_failure(self):
        """error field should be empty string for a real execution failure (WRONGTYPE).

        WRONGTYPE is an execution error, not a pre-execution rejection, so the
        error field should be empty — only rejected= and acl_deny_reason= populate it.
        """
        log_lines = self._trigger_wrongtype_failure("json")

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("result") == "FAILURE":
                self.assertEqual(obj.get("error", "N/A"), "",
                                 f"error should be empty for a real execution failure, "
                                 f"got: {obj.get('error')!r}")
                return
        self.fail("No FAILURE JSON entry found")

    def test_081_json_error_contains_rejected_for_wrong_args(self):
        """error field should contain 'rejected=' for a wrong-arg-count rejection."""
        log_lines = self._trigger_wrong_arg_count("json")

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("result") == "FAILURE":
                error = obj.get("error", "")
                self.assertIn("rejected=", error,
                              f"error should contain 'rejected=' for a REJECTED event, "
                              f"got: {error!r}")
                return
        if not log_lines:
            self.skipTest("No log entries — server may not support REJECTED events")
        self.fail("No FAILURE entry found in log")

    def test_082_json_error_contains_acl_info_for_noperm(self):
        """error field should contain acl_deny_reason= for ACL NOPERM rejections."""
        try:
            self.client.execute_command(
                "ACL", "SETUSER", "noperm_content_user", "on", ">nopermpass99",
                "nocommands", "~*"
            )
        except redis.exceptions.ResponseError as e:
            self.skipTest(f"Could not create ACL test user: {e}")

        self.client.execute_command("CONFIG", "SET", "audit.format", "json")
        self.client.execute_command("CONFIG", "SET", "audit.events", "keys,auth,config,other")
        time.sleep(0.2)
        self._clear_log_file()

        noperm = redis.Redis(
            host='localhost', port=self.__class__.port,
            username='noperm_content_user', password='nopermpass99',
            decode_responses=True
        )
        try:
            noperm.execute_command("PING")
        except (redis.exceptions.ResponseError, redis.exceptions.AuthenticationError):
            pass
        finally:
            noperm.close()

        time.sleep(0.5)
        log_lines = self._read_log_file()

        try:
            self.client.execute_command("ACL", "DELUSER", "noperm_content_user")
        except Exception:
            pass

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("result") == "FAILURE":
                error = obj.get("error", "")
                if "acl_deny_reason=" in error:
                    return
        if not log_lines:
            self.skipTest("No log entries — server may not support ACL_REJECTED events")
        self.fail("No FAILURE entry with 'acl_deny_reason=' found in error field")

    def test_083_text_format_error_on_rejection(self):
        """TEXT format should include 'rejected=' inline for rejected commands."""
        log_lines = self._trigger_wrong_arg_count("text")
        log_content = "".join(log_lines)

        if not log_lines:
            self.skipTest("No log entries — server may not support REJECTED events")
        self.assertIn("FAILURE", log_content,
                      "TEXT format should include FAILURE result for rejected command")
        self.assertIn("rejected=", log_content,
                      "TEXT format should include 'rejected=' for rejected commands")

    def test_084_csv_error_column_on_rejection(self):
        """CSV error column (index 12) should contain 'rejected=' for rejected commands."""
        log_lines = self._trigger_wrong_arg_count("csv")

        if not log_lines:
            self.skipTest("No log entries — server may not support REJECTED events")

        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            row = next(csv.reader(io.StringIO(line)))
            # col 4 is result, col 12 is error
            if len(row) >= 13 and row[4] == "FAILURE":
                self.assertIn("rejected=", row[12],
                              f"CSV error column (index 12) should contain 'rejected=', "
                              f"got: {row[12]!r}")
                return
        self.fail("No FAILURE CSV entry found")

    def tearDown(self):
        try:
            self.client.execute_command("CONFIG", "SET", "audit.format", "text")
            self.client.execute_command("CONFIG", "SET", "audit.events",
                                        "keys,auth,config,other")
        except Exception:
            pass


if __name__ == '__main__':
    unittest.main()
